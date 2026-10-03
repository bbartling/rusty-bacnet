use super::*;

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Return the last bound local MAC snapshot, including after stop.
    /// This retained address does not assert that the transport is still active.
    pub fn local_mac(&self) -> &[u8] {
        &self.local_mac
    }

    /// Get a reference to the shared object database.
    ///
    /// Objects read through this handle return raw standalone data. A built-in
    /// Device follows its declared service profile, with absent or empty COV lists.
    /// Served Device definitions and live lists belong to the executor: use
    /// [`read_local`](Self::read_local) for that view. Normal Device mutation and
    /// replacement cannot change the served execution profile.
    /// Install Device objects before startup: changing their membership through
    /// this handle does not rebind the discovery limiter's startup identity.
    pub fn database(&self) -> &Arc<RwLock<ObjectDatabase>> {
        &self.db
    }

    /// Read one local property through the server's ReadProperty evaluator.
    ///
    /// With multiple Device objects, the lowest instance is selected for Device
    /// wildcard reads and the live COV lists, independent of insertion order.
    /// Other Device objects receive empty COV lists. Every served Device uses
    /// the executor's services, COV presence and property definitions, even after
    /// public profile mutation, replacement or custom object installation.
    ///
    /// This is the live local read boundary: it applies the same Device
    /// wildcard resolution, `UNKNOWN_OBJECT` and `PROPERTY_IS_NOT_AN_ARRAY`
    /// checks, and value source as network ReadProperty. The selected Device's
    /// `Active_COV_Subscriptions` (ordinary and single-property subscriptions)
    /// and `Active_COV_Multiple_Subscriptions` (SubscribeCOVPropertyMultiple
    /// contexts) are projected from the COV subscription table at one sampled
    /// instant, returned as their encoded `BACnetLIST of BACnetCOVSubscription`
    /// and `BACnetLIST of BACnetCOVMultipleSubscription`
    /// (`PropertyValue::ApplicationData`). After [`stop`](Self::stop) the
    /// server services no subscriptions, so both properties read as empty lists.
    ///
    /// A Group's `Present_Value` is rebuilt from its members, whose rows count
    /// against the ReadPropertyMultiple work limit
    /// ([`ReadPropertyMultipleBudget::max_result_elements`](crate::server::ReadPropertyMultipleBudget))
    /// as for network ReadProperty; past it the read fails with
    /// [`Error::Abort`] carrying OUT_OF_RESOURCES.
    pub async fn read_local(
        &self,
        oid: &ObjectIdentifier,
        property: PropertyIdentifier,
        array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        let db = self.db.read().await;
        let lookup_oid =
            handlers::resolve_read_target(&db, oid, self.config.registered_network_port);
        let view = crate::device_view::DeviceReadContext::new(
            &db,
            crate::device_view::DeviceExecution::FullServer,
        )
        .with_work_limit(
            self.config
                .read_property_multiple_budget
                .max_result_elements,
        );
        let plan =
            handlers::plan_read_property(&db, Some(&view), lookup_oid, property, array_index)
                .map_err(|failure| match failure {
                    handlers::ReadFailure::Service(error) => error,
                    handlers::ReadFailure::Work | handlers::ReadFailure::Bytes => Error::Abort {
                        reason: AbortReason::OUT_OF_RESOURCES.to_raw(),
                    },
                })?;
        let live = match plan.live_cov(&db) {
            Some(selection) if self.dispatch_task.is_none() => {
                Some(crate::cov::active::LiveDeviceCov::stopped(selection))
            }
            Some(selection) => Some(
                super::requests::confirmed_response::active_cov_snapshot(
                    &db,
                    &self.cov_table,
                    selection,
                )
                .await,
            ),
            None => None,
        };
        let view = view.with_live(live.as_ref());
        handlers::read_property_value(&db, Some(&view), plan)
    }

    /// Create a cloneable handle for unsolicited I-Am announcements.
    pub fn i_am_broadcaster(&self) -> IAmBroadcaster<T> {
        IAmBroadcaster {
            state: Arc::downgrade(&self.broadcaster),
        }
    }

    /// Get the communication state per DeviceCommunicationControl.
    ///
    /// Returns 0 (Enable), 1 (Disable), or 2 (DisableInitiation).
    pub fn comm_state(&self) -> u8 {
        self.comm_state.load(Ordering::Acquire)
    }

    /// Generate PICS from the database and the server's effective Device execution view.
    /// Standalone [`PicsGenerator`](crate::pics::PicsGenerator) keeps raw-object semantics.
    ///
    /// The caller must supply a [`PicsConfig`](crate::pics::PicsConfig) for fields not available from the server
    /// (vendor name, model, firmware revision, etc.).
    pub async fn generate_pics(&self, pics_config: &crate::pics::PicsConfig) -> crate::pics::Pics {
        let db = self.db.read().await;
        crate::pics::PicsGenerator::new(&db, &self.config, pics_config)
            .for_server()
            .generate()
    }
}
