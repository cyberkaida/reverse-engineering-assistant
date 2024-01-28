package reva;

import reva.RevaProtocol.RevaMessage;
import reva.RevaProtocol.RevaMessageResponse;
import java.util.concurrent.Semaphore;

public class RevaCallbackHandler {
    RevaMessage message;
    RevaMessageResponse response;

    public RevaCallbackHandler(RevaMessage message) {
        this.message = message;
    }

    public Boolean isResponseForMessage(RevaMessageResponse response) {
        return response.response_to.equals(message.message_id);
    }

    public Boolean hasResponse() {
        return response != null;
    }

    public void submitResponse(RevaMessageResponse response) {
        if (this.response != null) {
            throw new RuntimeException("Response already submitted");
        }
        this.response = response;
    }

    public RevaMessageResponse getResponse() {
        return response;
    }

    public RevaMessageResponse waitForResponse() {
        // TODO: Go back to using semaphore
        while (response == null) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
        return response;
    }
}
