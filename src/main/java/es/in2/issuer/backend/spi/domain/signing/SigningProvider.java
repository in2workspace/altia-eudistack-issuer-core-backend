package es.in2.issuer.backend.spi.domain.signing;


import es.in2.issuer.backend.spi.domain.exception.SigningException;
import es.in2.issuer.backend.spi.domain.model.SigningRequest;
import es.in2.issuer.backend.spi.domain.model.SigningResult;

public interface SigningProvider {
    SigningResult signCredential(SigningRequest request) throws SigningException;
}
