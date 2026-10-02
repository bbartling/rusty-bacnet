//! Group, Global Group and Structured View object tests.

use super::*;

// -----------------------------------------------------------------------
// GroupObject tests
// -----------------------------------------------------------------------

#[test]
fn group_create() {
    let g = GroupObject::new(1, "Group-1").unwrap();
    assert_eq!(g.object_identifier().object_type(), ObjectType::GROUP);
    assert_eq!(g.object_identifier().instance_number(), 1);
    assert_eq!(g.object_name(), "Group-1");
}

#[test]
fn group_object_type() {
    let g = GroupObject::new(1, "G").unwrap();
    let val = g
        .read_property(PropertyIdentifier::OBJECT_TYPE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Enumerated(ObjectType::GROUP.to_raw()));
}

#[test]
fn group_add_members() {
    let mut g = GroupObject::new(1, "G").unwrap();
    let ai1 = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap();
    let ai2 = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 2).unwrap();
    g.add_member(ai1);
    g.add_member(ai2);

    let val = g
        .read_property(PropertyIdentifier::LIST_OF_GROUP_MEMBERS, None)
        .unwrap();
    if let PropertyValue::List(items) = val {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], PropertyValue::ObjectIdentifier(ai1));
        assert_eq!(items[1], PropertyValue::ObjectIdentifier(ai2));
    } else {
        panic!("Expected List");
    }
}

#[test]
fn group_clear_members() {
    let mut g = GroupObject::new(1, "G").unwrap();
    let ai1 = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap();
    g.add_member(ai1);
    assert_eq!(g.list_of_group_members.len(), 1);
    g.clear_members();
    assert!(g.list_of_group_members.is_empty());
}

#[test]
fn group_present_value_empty() {
    let g = GroupObject::new(1, "G").unwrap();
    let val = g
        .read_property(PropertyIdentifier::PRESENT_VALUE, None)
        .unwrap();
    if let PropertyValue::List(items) = val {
        assert!(items.is_empty());
    } else {
        panic!("Expected List");
    }
}

#[test]
fn group_property_list() {
    let g = GroupObject::new(1, "G").unwrap();
    let props = g.property_list();
    assert!(props.contains(&PropertyIdentifier::LIST_OF_GROUP_MEMBERS));
    assert!(props.contains(&PropertyIdentifier::PRESENT_VALUE));
    // Table 12-17 has no Status_Flags (#1064).
    assert!(!props.contains(&PropertyIdentifier::STATUS_FLAGS));
}

// -----------------------------------------------------------------------
// GlobalGroupObject tests
// -----------------------------------------------------------------------

#[test]
fn global_group_create() {
    let gg = GlobalGroupObject::new(1, "GG-1").unwrap();
    assert_eq!(
        gg.object_identifier().object_type(),
        ObjectType::GLOBAL_GROUP
    );
    assert_eq!(gg.object_identifier().instance_number(), 1);
    assert_eq!(gg.object_name(), "GG-1");
}

#[test]
fn global_group_object_type() {
    let gg = GlobalGroupObject::new(1, "GG").unwrap();
    let val = gg
        .read_property(PropertyIdentifier::OBJECT_TYPE, None)
        .unwrap();
    assert_eq!(
        val,
        PropertyValue::Enumerated(ObjectType::GLOBAL_GROUP.to_raw())
    );
}

#[test]
fn global_group_members_empty() {
    let gg = GlobalGroupObject::new(1, "GG").unwrap();
    let val = gg
        .read_property(PropertyIdentifier::GROUP_MEMBERS, None)
        .unwrap();
    if let PropertyValue::List(items) = val {
        assert!(items.is_empty());
    } else {
        panic!("Expected List");
    }
}

#[test]
fn global_group_member_names() {
    let mut gg = GlobalGroupObject::new(1, "GG").unwrap();
    gg.group_member_names.push("Temp Sensor".into());
    gg.group_member_names.push("Humidity".into());

    let val = gg
        .read_property(PropertyIdentifier::GROUP_MEMBER_NAMES, None)
        .unwrap();
    if let PropertyValue::List(items) = val {
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0],
            PropertyValue::CharacterString("Temp Sensor".into())
        );
        assert_eq!(items[1], PropertyValue::CharacterString("Humidity".into()));
    } else {
        panic!("Expected List");
    }
}

#[test]
fn global_group_property_list() {
    let gg = GlobalGroupObject::new(1, "GG").unwrap();
    let props = gg.property_list();
    assert!(props.contains(&PropertyIdentifier::GROUP_MEMBERS));
    assert!(props.contains(&PropertyIdentifier::PRESENT_VALUE));
    assert!(props.contains(&PropertyIdentifier::GROUP_MEMBER_NAMES));
    assert!(props.contains(&PropertyIdentifier::EVENT_STATE));
    assert!(props.contains(&PropertyIdentifier::MEMBER_STATUS_FLAGS));
}

// -----------------------------------------------------------------------
// StructuredViewObject tests
// -----------------------------------------------------------------------

#[test]
fn structured_view_create() {
    let sv = StructuredViewObject::new(1, "SV-1").unwrap();
    assert_eq!(
        sv.object_identifier().object_type(),
        ObjectType::STRUCTURED_VIEW
    );
    assert_eq!(sv.object_identifier().instance_number(), 1);
    assert_eq!(sv.object_name(), "SV-1");
}

#[test]
fn structured_view_object_type() {
    let sv = StructuredViewObject::new(1, "SV").unwrap();
    let val = sv
        .read_property(PropertyIdentifier::OBJECT_TYPE, None)
        .unwrap();
    assert_eq!(
        val,
        PropertyValue::Enumerated(ObjectType::STRUCTURED_VIEW.to_raw())
    );
}

#[test]
fn structured_view_add_subordinates() {
    let mut sv = StructuredViewObject::new(1, "SV").unwrap();
    let ai1 = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap();
    let bi1 = ObjectIdentifier::new(ObjectType::BINARY_INPUT, 1).unwrap();
    sv.add_subordinate(ai1, "Temperature");
    sv.add_subordinate(bi1, "Occupancy");

    let val = sv
        .read_property(PropertyIdentifier::SUBORDINATE_LIST, None)
        .unwrap();
    if let PropertyValue::List(items) = val {
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], PropertyValue::ObjectIdentifier(ai1));
        assert_eq!(items[1], PropertyValue::ObjectIdentifier(bi1));
    } else {
        panic!("Expected List");
    }

    let ann = sv
        .read_property(PropertyIdentifier::SUBORDINATE_ANNOTATIONS, None)
        .unwrap();
    if let PropertyValue::List(items) = ann {
        assert_eq!(items.len(), 2);
        assert_eq!(
            items[0],
            PropertyValue::CharacterString("Temperature".into())
        );
        assert_eq!(items[1], PropertyValue::CharacterString("Occupancy".into()));
    } else {
        panic!("Expected List");
    }
}

#[test]
fn structured_view_node_type() {
    let sv = StructuredViewObject::new(1, "SV").unwrap();
    let val = sv
        .read_property(PropertyIdentifier::NODE_TYPE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Enumerated(0));
}

#[test]
fn structured_view_node_subtype() {
    let sv = StructuredViewObject::new(1, "SV").unwrap();
    let val = sv
        .read_property(PropertyIdentifier::NODE_SUBTYPE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::CharacterString(String::new()));
}

#[test]
fn structured_view_property_list() {
    let sv = StructuredViewObject::new(1, "SV").unwrap();
    let props = sv.property_list();
    assert!(props.contains(&PropertyIdentifier::NODE_TYPE));
    assert!(props.contains(&PropertyIdentifier::NODE_SUBTYPE));
    assert!(props.contains(&PropertyIdentifier::SUBORDINATE_LIST));
    assert!(props.contains(&PropertyIdentifier::SUBORDINATE_ANNOTATIONS));
}
