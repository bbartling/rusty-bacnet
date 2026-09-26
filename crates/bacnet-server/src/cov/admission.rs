use super::*;

impl CovSubscriptionTable {
    /// Accept an ordinary or Single insertion or renewal after quota and
    /// generation preflight. Multiple references are rejected before any table
    /// effect: they enter only through [`subscribe_multiple`](Self::subscribe_multiple),
    /// which owns their shared context lifetime and maximum notification delay.
    pub fn subscribe(&mut self, sub: CovSubscription) -> Result<CovSubscriptionSnapshot, Error> {
        let key = sub.key()?;
        if key.multiple_context().is_some() {
            return Err(Error::Encoding(
                "Multiple references must be admitted through subscribe_multiple".into(),
            ));
        }
        self.purge_expired();
        let existing = self.subs.get(&key).cloned();
        self.check_admission(
            &sub.recipient(),
            sub.expires_at.is_none(),
            existing.as_deref(),
        )?;
        let generation = self.reserve_generations(1)?;
        Ok(self.publish(key, sub, generation, None, None))
    }

    /// Atomically accept final unique Multiple references and refresh their exact context.
    /// All identities/options are validated before quota/generation reservation or refresh.
    /// The request's expiry and maximum notification delay become the whole
    /// context's (last write wins); the delay is reported, never acted on.
    /// The admitted route also replaces the route of every retained reference,
    /// including empty renewals. A changed route fences old snapshots while
    /// preserving unreplaced observations; same-route refresh retains authority.
    pub fn subscribe_multiple(
        &mut self,
        context: &MultipleContextKey,
        route: &SubscriberEndpoint,
        expires_at: Instant,
        max_notification_delay: u32,
        mut subscriptions: Vec<CovSubscription>,
    ) -> Result<Vec<CovSubscriptionSnapshot>, Error> {
        context.recipient.validate()?;
        let recipient = CovRecipient::from_endpoint(&route.mac, route.network.as_ref());
        recipient.validate()?;
        if recipient != context.recipient {
            return Err(Error::Encoding(
                "Multiple route does not match its recipient".into(),
            ));
        }
        for sub in &subscriptions {
            if sub.key()?.multiple_context() != Some(context)
                || sub.expires_at != Some(expires_at)
                || sub.endpoint() != *route
            {
                return Err(Error::Encoding(
                    "Multiple subscription does not match its context/route/expiry".into(),
                ));
            }
        }
        // Final options win exactly once, retaining the final-occurrence request order.
        subscriptions.reverse();
        let mut keys = std::collections::HashSet::new();
        subscriptions.retain(|sub| keys.insert(sub.key().expect("validated identity")));
        subscriptions.reverse();
        self.purge_expired();
        let new_count = keys
            .iter()
            .filter(|key| !self.subs.contains_key(key))
            .count();
        let peer = CovRecipient::from_endpoint(&route.mac, route.network.as_ref());
        self.check_admission_multiple(&peer, new_count, 0)?;
        let first_generation = self.reserve_generations(subscriptions.len())?;
        // No fallible step follows this point. Unreplaced context references retain generations.
        let route_owner = self
            .subs
            .values()
            .find(|entry| entry.key.multiple_context() == Some(context))
            .filter(|entry| entry.endpoint() == *route)
            .and_then(|entry| entry.route_owner.clone())
            .unwrap_or_else(|| Arc::new(()));
        let mut previously_indefinite = 0;
        for entry in self.subs.values_mut() {
            if entry.key.multiple_context() == Some(context) {
                previously_indefinite += usize::from(entry.expires_at.is_none());
                entry.subscription.expires_at = Some(expires_at);
                entry.max_notification_delay = Some(max_notification_delay);
                entry.subscription.subscriber_mac = route.mac.clone();
                entry.subscription.subscriber_network = route.network.clone();
                entry.route_owner = Some(Arc::clone(&route_owner));
            }
        }
        if let Some(count) = self.peer_indefinite_counts.get_mut(&peer) {
            *count -= previously_indefinite;
            if *count == 0 {
                self.peer_indefinite_counts.remove(&peer);
            }
        }
        Ok(subscriptions
            .into_iter()
            .enumerate()
            .map(|(offset, sub)| {
                self.publish(
                    sub.key().expect("validated identity"),
                    sub,
                    first_generation + offset as u64,
                    Some(max_notification_delay),
                    Some(Arc::clone(&route_owner)),
                )
            })
            .collect())
    }

    /// Test fixture: admit one proposal through its family's production
    /// owner. A Multiple reference is a one-reference `subscribe_multiple`
    /// request (finite expiry required) that refreshes its exact context with
    /// the supplied maximum notification delay.
    #[cfg(test)]
    pub(crate) fn admit_for_test(
        &mut self,
        sub: CovSubscription,
        max_notification_delay: u32,
    ) -> Result<CovSubscriptionSnapshot, Error> {
        let Some(context) = sub.key()?.multiple_context().cloned() else {
            return self.subscribe(sub);
        };
        let expires_at = sub
            .expires_at
            .expect("Multiple contexts always have a finite lifetime");
        let mut accepted = self.subscribe_multiple(
            &context,
            &sub.endpoint(),
            expires_at,
            max_notification_delay,
            vec![sub],
        )?;
        Ok(accepted.remove(0))
    }

    fn reserve_generations(&mut self, count: usize) -> Result<u64, Error> {
        if count == 0 {
            return Ok(self.generation);
        }
        let last = u64::try_from(count)
            .ok()
            .and_then(|count| self.generation.checked_add(count));
        let Some(last) = last else {
            self.counters
                .subscriptions_rejected_capacity
                .fetch_add(1, Ordering::Relaxed);
            return Err(Error::Protocol {
                class: ErrorClass::RESOURCES.to_raw() as u32,
                code: ErrorCode::NO_SPACE_TO_ADD_LIST_ELEMENT.to_raw() as u32,
            });
        };
        let first = self.generation + 1;
        self.generation = last;
        Ok(first)
    }

    fn publish(
        &mut self,
        key: CovSubscriptionKey,
        sub: CovSubscription,
        generation: u64,
        max_notification_delay: Option<u32>,
        route_owner: Option<Arc<()>>,
    ) -> CovSubscriptionSnapshot {
        let snapshot = CovSubscriptionSnapshot {
            key,
            generation,
            owner: Arc::clone(&self.owner),
            route_owner,
            subscription: sub.clone(),
            max_notification_delay,
        };
        let peer = sub.recipient();
        let new_indefinite = sub.expires_at.is_none();
        if let Some(old) = self.subs.insert(snapshot.key.clone(), snapshot.clone()) {
            let old_indefinite = old.expires_at.is_none();
            if old_indefinite != new_indefinite {
                if new_indefinite {
                    *self.peer_indefinite_counts.entry(peer).or_default() += 1;
                } else if let Some(count) = self.peer_indefinite_counts.get_mut(&peer) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.peer_indefinite_counts.remove(&peer);
                    }
                }
            }
        } else {
            *self.peer_counts.entry(peer.clone()).or_default() += 1;
            if new_indefinite {
                *self.peer_indefinite_counts.entry(peer).or_default() += 1;
            }
            self.counters
                .subscriptions_created
                .fetch_add(1, Ordering::Relaxed);
        }
        self.counters
            .subscriptions_active
            .store(self.subs.len() as u64, Ordering::Relaxed);
        snapshot
    }

    /// Check admission for a single subscription request against policy quotas.
    pub(super) fn check_admission(
        &mut self,
        peer: &CovRecipient,
        is_indefinite: bool,
        existing: Option<&CovSubscription>,
    ) -> Result<(), Error> {
        self.purge_expired();

        if is_indefinite && !self.policy.allow_indefinite_subscriptions {
            self.counters
                .subscriptions_rejected_indefinite
                .fetch_add(1, Ordering::Relaxed);
            return Err(Error::Protocol {
                class: ErrorClass::SERVICES.to_raw() as u32,
                code: ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED.to_raw() as u32,
            });
        }

        let (new_count, new_indefinite) = match existing {
            Some(sub) => {
                let was_indefinite = sub.expires_at.is_none();
                let add_indefinite = if is_indefinite && !was_indefinite {
                    1
                } else {
                    0
                };
                (0, add_indefinite)
            }
            None => {
                let add_indefinite = if is_indefinite { 1 } else { 0 };
                (1, add_indefinite)
            }
        };

        self.check_admission_multiple(peer, new_count, new_indefinite)
    }

    /// Check admission for a batch of subscriptions against policy quotas.
    fn check_admission_multiple(
        &mut self,
        peer: &CovRecipient,
        new_count: usize,
        new_indefinite: usize,
    ) -> Result<(), Error> {
        self.purge_expired();

        if new_indefinite > 0 {
            if !self.policy.allow_indefinite_subscriptions {
                self.counters
                    .subscriptions_rejected_indefinite
                    .fetch_add(1, Ordering::Relaxed);
                return Err(Error::Protocol {
                    class: ErrorClass::SERVICES.to_raw() as u32,
                    code: ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED.to_raw() as u32,
                });
            }
            let current_indefinite = self.peer_indefinite_counts.get(peer).copied().unwrap_or(0);
            if current_indefinite + new_indefinite > self.policy.max_indefinite_per_peer {
                self.counters
                    .subscriptions_rejected_indefinite
                    .fetch_add(1, Ordering::Relaxed);
                return Err(Error::Protocol {
                    class: ErrorClass::RESOURCES.to_raw() as u32,
                    code: ErrorCode::NO_SPACE_TO_ADD_LIST_ELEMENT.to_raw() as u32,
                });
            }
        }

        if new_count == 0 {
            return Ok(());
        }

        let current_peer = self.peer_counts.get(peer).copied().unwrap_or(0);
        if current_peer + new_count > self.policy.max_subscriptions_per_peer {
            self.counters
                .subscriptions_rejected_quota
                .fetch_add(1, Ordering::Relaxed);
            return Err(Error::Protocol {
                class: ErrorClass::RESOURCES.to_raw() as u32,
                code: ErrorCode::NO_SPACE_TO_ADD_LIST_ELEMENT.to_raw() as u32,
            });
        }

        if self.subs.len() + new_count > self.policy.max_subscriptions_global {
            self.counters
                .subscriptions_rejected_capacity
                .fetch_add(1, Ordering::Relaxed);
            return Err(Error::Protocol {
                class: ErrorClass::RESOURCES.to_raw() as u32,
                code: ErrorCode::NO_SPACE_TO_ADD_LIST_ELEMENT.to_raw() as u32,
            });
        }

        if !self.policy.is_peer_reserved(peer) {
            let unreserved_capacity = self.policy.effective_unreserved_capacity();
            if self.subs.len() + new_count > unreserved_capacity {
                self.counters
                    .subscriptions_rejected_capacity
                    .fetch_add(1, Ordering::Relaxed);
                return Err(Error::Protocol {
                    class: ErrorClass::RESOURCES.to_raw() as u32,
                    code: ErrorCode::NO_SPACE_TO_ADD_LIST_ELEMENT.to_raw() as u32,
                });
            }
        }

        Ok(())
    }
}
