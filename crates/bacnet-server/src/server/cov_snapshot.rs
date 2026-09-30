use super::cov_notify_context::CovNotifyContext;
use super::*;

impl<T: TransportPort + 'static> BACnetServer<T> {
    pub(super) async fn fire_cov_notifications_from_snapshot(
        ctx: &CovNotifyContext<'_, T>,
        oid: &ObjectIdentifier,
        snapshot: &dyn bacnet_objects::traits::BACnetObject,
    ) {
        Self::fire_cov_notifications_inner(ctx, oid, Some(snapshot)).await;
    }
}
