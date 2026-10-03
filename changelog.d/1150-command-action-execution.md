---
section: Added
---
- **Breaking Command action lists run (wire):** writing a Command object's
  Present_Value on a running server now makes the writes of the Action list it
  selects (#1150, Clause 12.10). Until now the object only stored the number.
  - Present_Value takes 0 to the Action size; a larger number is PROPERTY /
    VALUE_OUT_OF_RANGE, where it used to be stored as written. Zero and an
    empty list write nothing and set All_Writes_Successful TRUE at once.
  - A list with commands sets In_Process TRUE and All_Writes_Successful
    FALSE. Until it ends, any Present_Value write, the running number
    included, is OBJECT / BUSY, so a Command naming itself can't restart.
    Writing the same number again after the run starts the list again.
  - The server makes each command in list order through the `write_local`
    path, with the Command as the initiating object, so priorities,
    command-source tracking, audit, COV and the post-write event pass apply
    as for any local write. Each command's Write_Successful records its
    outcome; a failure with Quit_On_Failure set ends the list and leaves the
    flags after it FALSE. Post_Delay is a timer in the run's own task, so the
    request that wrote Present_Value is answered at once. When the list ends,
    In_Process returns to FALSE and All_Writes_Successful is TRUE only if
    every write succeeded.
  - Writes go to this device only: a command naming another Device fails like
    a refused write, while one naming this Device is local.
  - WriteProperty, WritePropertyMultiple, `write_local`, a Schedule tick and a
    written Schedule's own pass all start the run, and a run's write to
    another Command starts that one too.
  - Command takes SubscribeCOVProperty (Table 13-1a), so a client can watch
    In_Process and All_Writes_Successful; SubscribeCOV is still refused.
  - `CommandObject::set_action_text` serves Action_Text, an array of one
    description per list that reads per index and follows the Action size.
    `set_action` now abandons a run in progress.
