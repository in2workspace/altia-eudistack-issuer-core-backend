package es.in2.issuer.backend.signing.infrastructure.adapter;

import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.service.JwsSignHashService;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.domain.spi.SigningRequestValidator;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.infrastructure.qtsp.auth.QtspAuthClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.backoffice.domain.util.Constants.SIGNATURE_REMOTE_SCOPE_CREDENTIAL;

@Slf4j
@Service
@RequiredArgsConstructor
public class CscSignHashSigningProvider implements SigningProvider {

    private final QtspAuthClient qtspAuthClient;
    private final QtspIssuerService qtspIssuerService;
    private final JwsSignHashService jwsSignHashService;

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {
        return Mono.defer(() -> {
            SigningRequestValidator.validate(request, false);

            if (request.type() != SigningType.JADES) {
                return Mono.error(new SigningException("csc-sign-hash supports only JADES/JWT"));
            }

            SigningContext ctx = request.context();
            String procedureId = ctx != null ? ctx.procedureId() : null;
            log.debug("CSC signHash provider sign. procedureId={}", procedureId);

            return qtspAuthClient.requestAccessToken(request, SIGNATURE_REMOTE_SCOPE_CREDENTIAL, false)
                    .flatMap(accessToken ->
                            qtspIssuerService.requestCertificateInfo(
                                            accessToken,
                                            qtspIssuerService.getCredentialId()
                                    )
                                    .flatMap(qtspIssuerService::extractX5cChain)
                                    .flatMap(x5c -> jwsSignHashService.signJwtWithSignHash(accessToken, request.data(), x5c))
                    )
                    .map(jwt -> new SigningResult(SigningType.JADES, jwt));
        });
    }
}
