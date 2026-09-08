package es.in2.issuer.backend.issuance.application.workflow;

import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import reactor.core.publisher.Mono;

public interface IssuanceWorkflow {

    /**
     * @param idToken     optional {@code X-Id-Token}, the DOME identity assertion some profiles require
     *                    for authorization. Never a bearer credential.
     * @param bearerToken the caller's {@code Authorization} header. The direct delivery mode signs
     *                    inside this request, so it needs a caller token of its own; the wallet modes
     *                    sign later, against their own OID4VCI access token, and ignore it.
     */
    Mono<IssuanceResponse> issueCredential(String processId, IssuanceRequest request, String idToken,
                                           String bearerToken, String publicIssuerBaseUrl,
                                           String publicWalletBaseUrl);

    Mono<IssuanceResponse> issueCredentialWithoutAuthorization(String processId, IssuanceRequest request, String token,
                                                               String publicIssuerBaseUrl, String publicWalletBaseUrl);

}
