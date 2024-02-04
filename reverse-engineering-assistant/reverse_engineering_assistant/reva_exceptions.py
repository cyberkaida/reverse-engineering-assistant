from langchain_core.exceptions import OutputParserException

class RevaToolException(OutputParserException):
    """
    Exceptions subclassed by this will be sent to the LLM instead of the user.

    If the LLM can fix the error something inheriting from this should be raised.
    """
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message
        self.observation = message
        self.send_to_llm = True
    pass
