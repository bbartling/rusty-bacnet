//! The Averaging sample window in a running server (Clause 12.5, #1092).
//!
//! A WriteProperty of a window row empties the window, so its statistics go
//! back to positive infinity, NaN and negative infinity. COV compares a
//! non-finite REAL by its bits: a move to or from one is always reported,
//! whatever the subscription's increment, and staying at one never is.
use super::*;
use bacnet_services::write_property::WritePropertyRequest;

const ATTEMPTED: PropertyIdentifier = PropertyIdentifier::ATTEMPTED_SAMPLES;
const WINDOW_SAMPLES: PropertyIdentifier = PropertyIdentifier::WINDOW_SAMPLES;

/// WriteProperty on AVG-1 from the peer, and the answer.
async fn write(
    h: &mut Harness,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Result<(), ErrorCode> {
    let mut body = BytesMut::new();
    WritePropertyRequest {
        object_identifier: avg1(),
        property_identifier: property,
        property_array_index: None,
        property_value: encoded(value),
        priority: None,
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::WRITE_PROPERTY, body)
        .await;
    response(h).await
}

async fn missed(h: &Harness) {
    h.server
        .add_averaging_sample_local(&avg1(), None)
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn averaging_window_write_reports_nan_and_infinities_to_property_subscribers() {
    let mut h = start().await;
    // Process 1 watches Minimum_Value on any change, process 3 Average_Value
    // with an increment far larger than any move between finite values here.
    subscribe_property(&mut h, 1, MIN, None).await;
    assert_eq!(response(&h).await, Ok(()));
    assert_eq!(
        values(&h.cov_notification().await),
        [(MIN, real(f32::INFINITY))]
    );
    subscribe_property(&mut h, 3, AVG, Some(1000.0)).await;
    assert_eq!(response(&h).await, Ok(()));
    assert_eq!(values(&h.cov_notification().await), [(AVG, real(f32::NAN))]);

    // Leaving NaN is reported despite the increment.
    sample(&h, 10.0).await;
    assert_eq!(
        notifications(&h, 2).await,
        BTreeMap::from([(1, vec![(MIN, real(10.0))]), (3, vec![(AVG, real(10.0))])])
    );
    sample(&h, 30.0).await; // the average moves 10: under the increment
    h.no_notification().await;

    // A write of Window_Samples empties the window, and both subscribers hear
    // the empty-window values.
    assert_eq!(
        write(&mut h, WINDOW_SAMPLES, PropertyValue::Unsigned(2)).await,
        Ok(())
    );
    assert_eq!(
        notifications(&h, 2).await,
        BTreeMap::from([
            (1, vec![(MIN, real(f32::INFINITY))]),
            (3, vec![(AVG, real(f32::NAN))]),
        ])
    );
    // Emptying an empty window changes nothing anyone watches: NaN stays NaN.
    assert_eq!(
        write(&mut h, ATTEMPTED, PropertyValue::Unsigned(0)).await,
        Ok(())
    );
    h.no_notification().await;

    // The two-sample window slides: 10, 20, then 40 pushes the 10 out.
    sample(&h, 10.0).await;
    assert_eq!(notifications(&h, 2).await.len(), 2);
    sample(&h, 20.0).await;
    h.no_notification().await; // Minimum_Value stays 10, the average moves 5
    sample(&h, 40.0).await;
    assert_eq!(values(&h.cov_notification().await), [(MIN, real(20.0))]);
    h.no_notification().await;
    assert_eq!(avg_value(&h, AVG).await, PropertyValue::Real(30.0));
    assert_eq!(avg_value(&h, ATTEMPTED).await, PropertyValue::Unsigned(2));

    // Refused writes leave the window, and the subscribers, alone.
    for (property, value) in [
        (WINDOW_SAMPLES, PropertyValue::Unsigned(0)),
        (WINDOW_SAMPLES, PropertyValue::Unsigned(1_441)),
        (
            PropertyIdentifier::WINDOW_INTERVAL,
            PropertyValue::Unsigned(0),
        ),
        (ATTEMPTED, PropertyValue::Unsigned(2)),
    ] {
        assert_eq!(
            write(&mut h, property, value).await,
            Err(ErrorCode::VALUE_OUT_OF_RANGE),
            "{property:?}"
        );
    }
    h.no_notification().await;
    assert_eq!(avg_value(&h, AVG).await, PropertyValue::Real(30.0));
    assert_eq!(
        avg_value(&h, WINDOW_SAMPLES).await,
        PropertyValue::Unsigned(2)
    );
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn averaging_missed_sample_local_counts_an_attempt_and_not_a_value() {
    let mut h = start().await;
    subscribe_property(&mut h, 5, ATTEMPTED, None).await;
    assert_eq!(response(&h).await, Ok(()));
    h.cov_notification().await;
    subscribe_property(&mut h, 6, VALID, None).await;
    assert_eq!(response(&h).await, Ok(()));
    h.cov_notification().await;

    sample(&h, 8.0).await;
    notifications(&h, 2).await;
    // A miss moves Attempted_Samples alone.
    missed(&h).await;
    assert_eq!(
        values(&h.cov_notification().await),
        [(ATTEMPTED, encoded(PropertyValue::Unsigned(2)))]
    );
    h.no_notification().await;
    assert_eq!(avg_value(&h, VALID).await, PropertyValue::Unsigned(1));
    assert_eq!(avg_value(&h, AVG).await, PropertyValue::Real(8.0));

    // The miss route refuses what the sample route refuses.
    let unknown = ObjectIdentifier::new(ObjectType::AVERAGING, 9).unwrap();
    let error = h
        .server
        .add_averaging_sample_local(&unknown, None)
        .await
        .unwrap_err();
    assert_error(error, ErrorClass::OBJECT, ErrorCode::UNKNOWN_OBJECT);
    let error = h
        .server
        .add_averaging_sample_local(&av1(), None)
        .await
        .unwrap_err();
    assert_error(
        error,
        ErrorClass::OBJECT,
        ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
    );
    h.no_notification().await;
    h.server.stop().await.unwrap();
}
