package reva;

import ghidra.util.Lock;
import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;

public class RevaCallbackHandler {
    RevaMessage message;
    RevaMessageResponse response;
    Lock responseLock;

    public RevaCallbackHandler(RevaMessage message) {
        this.message = message;
        responseLock = new Lock(this.message.message_id.toString());
        responseLock.acquire();
    }

    public Boolean isResponseForMessage(RevaMessageResponse response) {
        return response.response_to.equals(message.message_id);
    }

    public void submitResponse(RevaMessageResponse response) {
        this.response = response;
        responseLock.release();
    }

    public RevaMessageResponse waitForResponse() {
        responseLock.acquire();
        return response;
    }
}
