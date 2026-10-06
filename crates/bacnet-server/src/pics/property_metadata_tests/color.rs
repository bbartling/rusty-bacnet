use super::*;
use bacnet_objects::color::{ColorObject, ColorTemperatureObject};
use bacnet_types::primitives::PropertyValue;
use PropertyIdentifier as P;

fn expected_rows(kind: ObjectType) -> Vec<PropertyRow> {
    // Independent (identifier, optional, writable) rows in declaration order; PICS sorts by property ID.
    match kind {
        ObjectType::COLOR => vec![
            (P::OBJECT_IDENTIFIER, false, false),
            (P::OBJECT_NAME, false, false),
            (P::OBJECT_TYPE, false, false),
            (P::PRESENT_VALUE, false, true),
            (P::TRACKING_VALUE, false, false),
            (P::COLOR_COMMAND, false, true),
            (P::IN_PROGRESS, false, false),
            (P::DEFAULT_COLOR, false, true),
            (P::DESCRIPTION, true, true),
            (P::DEFAULT_FADE_TIME, false, true),
            (P::TRANSITION, true, true),
            (P::PROPERTY_LIST, false, false),
        ],
        _ => vec![
            (P::OBJECT_IDENTIFIER, false, false),
            (P::OBJECT_NAME, false, false),
            (P::OBJECT_TYPE, false, false),
            (P::PRESENT_VALUE, false, true),
            (P::TRACKING_VALUE, false, false),
            (P::COLOR_COMMAND, false, true),
            (P::IN_PROGRESS, false, false),
            (P::DEFAULT_COLOR_TEMPERATURE, false, true),
            (P::DESCRIPTION, true, true),
            (P::DEFAULT_FADE_TIME, false, true),
            (P::DEFAULT_RAMP_RATE, false, true),
            (P::DEFAULT_STEP_INCREMENT, false, true),
            (P::MIN_PRES_VALUE, true, false),
            (P::MAX_PRES_VALUE, true, false),
            (P::TRANSITION, true, true),
            (P::PROPERTY_LIST, false, false),
        ],
    }
}

#[test]
fn pics_color_property_metadata_is_exact() {
    let fresh: [FreshObject; 2] = [
        || {
            (
                Box::new(ColorObject::new(7, "CLR-7").unwrap()),
                ObjectType::COLOR,
            )
        },
        || {
            (
                Box::new(ColorTemperatureObject::new(7, "CT-7").unwrap()),
                ObjectType::COLOR_TEMPERATURE,
            )
        },
    ];
    for make in fresh {
        let expected = expected_rows(make().1);
        for configured in [false, true] {
            let (mut object, kind) = make();
            if configured {
                object
                    .write_property(
                        P::DESCRIPTION,
                        None,
                        PropertyValue::CharacterString("long color label".repeat(100)),
                        None,
                    )
                    .unwrap();
            }
            let required = object.required_properties();
            let mut db = ObjectDatabase::new();
            db.add(object).unwrap();
            let pics = generate_pics(&db, &ServerConfig::default(), &PicsConfig::default());
            assert_eq!(pics.supported_object_types.len(), 1);
            let support = &pics.supported_object_types[0];
            assert_eq!(support.object_type, kind);
            assert!(!support.createable);
            assert!(support.deleteable);
            let rows: Vec<_> = support
                .supported_properties
                .iter()
                .map(|row| {
                    assert!(row.access.readable);
                    (row.property_id, row.access.optional, row.access.writable)
                })
                .collect();
            assert_eq!(
                rows,
                sorted_rows(&expected),
                "{kind:?}, configured={configured}"
            );
            assert_eq!(
                rows.iter()
                    .filter_map(|&(p, optional, _)| (!optional).then_some(p))
                    .collect::<Vec<_>>(),
                sorted_required(required.as_ref())
            );
        }
    }
}
