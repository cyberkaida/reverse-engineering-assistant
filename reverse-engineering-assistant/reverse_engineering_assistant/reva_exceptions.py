from langchain_core.exceptions import OutputParserException
class RevaToolException(OutputParserException):
    """
    Exceptions subclassed by this will be sent to the LLM instead of the user.

    If the LLM can fix the error something inheriting from this should be raised.
    """
    pass