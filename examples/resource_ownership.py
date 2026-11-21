# The first function returns before releasing the temporary credential.
def early_return(should_stop):
    credential = issue_temporary_credential()
    if should_stop:
        return None
    return_temporary_credential(credential)


# The normal path releases the credential.
def normal_release():
    credential = issue_temporary_credential()
    return_temporary_credential(credential)


# The configured managed call takes responsibility for the credential.
def explicit_handoff():
    credential = issue_temporary_credential()
    use_temporary_credential(credential)
