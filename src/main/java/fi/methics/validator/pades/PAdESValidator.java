package fi.methics.validator.pades;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * PAdES validation example
 */
public class PAdESValidator {

    private byte[] file;
    private String filename;
    private KeyStore keystore;
    
    private boolean enableOcsp = true;
    private boolean enableCrl  = true;
    private boolean printReport= false;
    
    public static void main(String[] args) {
        
        if (args == null || args.length < 1) {
            System.out.println("Usage: fi.methics.validator.pades.PAdESValidator [OPTIONS]");
            System.out.println();
            System.out.println("Options:");
            System.out.println("  -pdf=PATH              - PAdES signed file path");
            System.out.println("  -jks=VALUE             - optional path to truststore file");
            System.out.println("  -jkspwd=VALUE          - optional truststore password");
            System.out.println("  -nocrl                 - optional flag to disable CRL checks");
            System.out.println("  -noocsp                - optional flag to disable OCSP checks");
            System.out.println("  -printreport           - optional flag to print detailed XML report");
            System.out.println();
            System.out.println("Example:");
            System.out.println("  java fi.methics.validator.pades.PAdESValidator -pdf=C:\\tmp\\example.pdf");
            System.exit(1);
        }
        
        try {
            PAdESValidator validator = new PAdESValidator();
            
            String jks    = null;
            String jkspwd = "changeit";
            
            String param;
            for (int i = 0; i < args.length; i++) { 
                param = args[i].toLowerCase();
                if (param.startsWith("-jks=")) {
                    jks = args[i].substring(args[i].indexOf("=") + 1).trim();
                } else if (param.startsWith("-jkspwd=")) {
                    jkspwd = args[i].substring(args[i].indexOf("=") + 1).trim();
                } else if (param.startsWith("-pdf=")) {
                    validator.setFile(args[i].substring(args[i].indexOf("=") + 1).trim());
                } else if (param.startsWith("-nocrl")) {
                    validator.enableCrl = false;
                } else if (param.startsWith("-noocsp")) {
                    validator.enableOcsp = false;
                } else if (param.startsWith("-printreport")) {
                    validator.printReport = true;
                }
            }
            if (jks != null) {
                System.out.println("Loading keystore: " + jks);
                KeyStore keystore = KeyStore.getInstance("JKS");
                keystore.load(new FileInputStream(jks), jkspwd.toCharArray());
                validator.setKeystore(keystore);
            }
            System.out.println("Validating file: " + validator.filename);
            System.out.println("All signatures valid: " + validator.validate());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public PAdESValidator() {
        // Empty constructor
    }
    
    public void setFile(final String filename) throws IOException {
        this.filename = filename;
        this.file     = Files.readAllBytes(Paths.get(filename));
    }
    
    /**
     * Set keystore for this validator
     * @param keystore keystore
     */
    public void setKeystore(final KeyStore keystore) {
        this.keystore = keystore;
    }
    
    /**
     * Convert a byte[] to a hex String
     * @param data byte[] to convert
     * @return converted hex String
     */
    public static String toHexString(final byte[] data) {
        StringBuffer buf = new StringBuffer();
        for (byte b : data) {
            String hex = Integer.toHexString(b & 0xff);
            if (hex.length() < 2) {
                buf.append("0").append(hex);
            } else {
                buf.append(hex);
            }
        }
        return buf.toString();
    }

    /**
     * Validate the PAdES signature
     * @return true if the signature is valid
     * @throws KeyStoreException 
     */
    private boolean validate() throws KeyStoreException {
 
        DSSDocument          signedDoc = new InMemoryDocument(this.file);
        PDFDocumentValidator validator = new PDFDocumentValidator(signedDoc);
 
        validator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);
        validator.setCertificateVerifier(this.createVerifier());
        Reports reports = validator.validateDocument();
        
        SimpleReport simpleReport = reports.getSimpleReport();
        boolean      anyFail      = false;
        System.out.println("Validating " + simpleReport.getSignaturesCount() + " signatures");
        for (String id : simpleReport.getSignatureIdList()) {
            System.out.println("Validating Signature " + id + ":");
            boolean valid = simpleReport.isValid(id);
            System.out.println("  Valid: " + valid);
            if (!valid) {
                System.out.println("  Info    : " + simpleReport.getInfo(id));
                System.out.println("  Errors  : " + simpleReport.getErrors(id));
                System.out.println("  Warnings: " + simpleReport.getWarnings(id));
                anyFail = true;
            }
        }
        
        if (this.printReport) {
            this.printReport(reports);
        }
        
        return !anyFail;
    }
    
    /**
     * Create a verifier with a trusted certificate source. 
     * @return Certificate verifier
     * @throws KeyStoreException 
     */
    private CommonCertificateVerifier createVerifier() throws KeyStoreException {

        CRLSource   crlSource = this.enableCrl ? new OnlineCRLSource() : null; 
        OCSPSource ocspSource = this.enableOcsp? new OnlineOCSPSource(): null;
        DataLoader dataLoader = new NativeHTTPDataLoader();
        CertificateSource certSource = new CommonTrustedCertificateSource();
        
        if (this.keystore != null) {
            Enumeration<String> e = this.keystore.aliases();
            while (e.hasMoreElements()) {
                String name = e.nextElement();
                System.out.println("Adding " + name + " as trusted certificate");
                Certificate cert = this.keystore.getCertificate(name);
                certSource.addCertificate(new CertificateToken((X509Certificate)cert));
            }
        }

        CommonCertificateVerifier verifier = new CommonCertificateVerifier(Arrays.asList(certSource), crlSource, ocspSource, dataLoader);

        verifier.setCheckRevocationForUntrustedChains(true);
        verifier.setAlertOnMissingRevocationData(new LogOnStatusAlert());
        verifier.setCheckRevocationForUntrustedChains(false);

        return verifier;
    }
    
    /**
     * Print a detailed validation report
     * @param details validation detail report
     */
    private void printReport(final Reports reports) {
        System.out.println("\nDetailed report:");
        System.out.println(reports.getXmlDetailedReport());
    }
    
}
