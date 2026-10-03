//! Stopping Command and Channel runs that feed back into themselves.
//!
//! A run's write can start another object's run: a Command's list writing a
//! Channel's Present_Value, a Channel member that is a Command, and so on.
//! Those objects refuse a Present_Value write only while their own run is in
//! progress, so a loop whose writes are spaced out by delays (two Channels
//! naming each other, or a Channel and a Command) would otherwise go round
//! for ever, each object idle again by the time the other writes back.
//!
//! Each [`CommandRun`] carries the objects whose runs led to it. When a run's
//! write queues further runs, each one inherits that chain plus the writing
//! run's own object. A queued run whose object is already in its chain closes
//! a loop, and one more than [`MAX_RUN_DEPTH`] runs deep is too long a chain
//! to follow: neither is started. Its object took the write, so the run is
//! ended at once as failed (In_Process back to FALSE, or Write_Status FAILED),
//! and the write that queued it counts as failed too, with OBJECT / BUSY, the
//! answer an object gives a Present_Value write while it is still busy.

use super::command_runs::CommandRunner;
use super::*;
use bacnet_objects::command::CommandRun;

/// The most runs one chain may hold above a run: a run started by a write
/// eight runs down from a request or application write still starts, the
/// next one down doesn't.
pub(super) const MAX_RUN_DEPTH: usize = 8;

/// The chain a run queued by `parent`'s write inherits.
fn inherited_chain(parent: &CommandRun) -> Arc<[ObjectIdentifier]> {
    parent
        .chain
        .iter()
        .copied()
        .chain(std::iter::once(parent.source))
        .collect()
}

/// Whether a run of `source` may start under `chain`.
fn may_start(chain: &[ObjectIdentifier], source: ObjectIdentifier) -> bool {
    chain.len() <= MAX_RUN_DEPTH && !chain.contains(&source)
}

impl<T: TransportPort + 'static> CommandRunner<T> {
    /// Start the runs one of `parent`'s writes queued, each carrying
    /// `parent`'s chain plus `parent`'s object. Runs that would close a loop
    /// or nest too deep are ended as failed instead, and then the write fails.
    pub(super) async fn start_nested(
        &self,
        parent: &CommandRun,
        runs: Vec<CommandRun>,
    ) -> Result<(), Error> {
        if runs.is_empty() {
            return Ok(());
        }
        let chain = inherited_chain(parent);
        let mut refused = false;
        let mut started = Vec::with_capacity(runs.len());
        for mut run in runs {
            if may_start(&chain, run.source) {
                run.chain = Arc::clone(&chain);
                started.push(run);
            } else {
                debug!(
                    source = %parent.source,
                    target = %run.source,
                    depth = chain.len(),
                    "a run would start its own object again or nest too deep; ending it as failed"
                );
                self.complete(run.source, run.generation, false).await;
                refused = true;
            }
        }
        self.start(started);
        if refused {
            Err(Error::Protocol {
                class: ErrorClass::OBJECT.to_raw() as u32,
                code: ErrorCode::BUSY.to_raw() as u32,
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_objects::command::RunPlan;

    fn ch(instance: u32) -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::CHANNEL, instance).unwrap()
    }

    fn run(source: ObjectIdentifier, chain: &[ObjectIdentifier]) -> CommandRun {
        CommandRun {
            source,
            generation: 1,
            plan: RunPlan::Actions(Vec::new()),
            chain: chain.into(),
        }
    }

    #[test]
    fn a_run_chain_refuses_its_own_objects_and_more_than_eight_ancestors() {
        // A request's run starts with no ancestors; what it queues inherits it.
        let top = run(ch(1), &[]);
        let chain = inherited_chain(&top);
        assert_eq!(chain.as_ref(), [ch(1)]);
        assert!(may_start(&chain, ch(2)));
        assert!(!may_start(&chain, ch(1)));
        // Two down, the outermost object is still in the chain.
        let chain = inherited_chain(&run(ch(2), &chain));
        assert_eq!(chain.as_ref(), [ch(1), ch(2)]);
        assert!(!may_start(&chain, ch(1)));
        assert!(may_start(&chain, ch(3)));
        // Eight ancestors start; nine don't.
        let eight: Vec<_> = (1..=8).map(ch).collect();
        assert!(may_start(&eight, ch(9)));
        let nine: Vec<_> = (1..=9).map(ch).collect();
        assert!(!may_start(&nine, ch(10)));
    }
}
