package es.in2.issuer.backend.signing.domain.service;

import es.in2.issuer.backend.signing.domain.model.JadesProfile;
import es.in2.issuer.backend.signing.domain.model.dto.CertificateInfo;


public interface JadesHeaderBuilderService {
    String buildHeader(CertificateInfo certInfo, JadesProfile profile);
}
