package eu.doppel_helix.dev.openpgpdemo;

import java.io.BufferedInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

public class TestAutomaticVerification {
    @SuppressWarnings("UseOfSystemOutOrSystemErr")
    public static void main(String[] args) throws Exception {
	// KEYS files to be trusted for downloads - must come from a safe source
	// this is the trust anchor!
	URL keysUrl = new URL("https://www.apache.org/dist/netbeans/KEYS");

	// URL for the download (can be insecure, will be verified by KEYS)
	URL downloadUrl = new URL("http://mirror.softaculous.com/apache/netbeans/netbeans/11.2/netbeans-11.2-bin.zip");
	// URL for the .asc file (can be insecure, will be verfied by KEYS)
	// Is directly from the ASF, as the mirrors don't get the .asc files
	URL signatureUrl = new URL("https://www.apache.org/dist/netbeans/netbeans/11.1/netbeans-11.1-bin.zip.asc");

	// Here the validated stream is written to
	String outputFile = "Netbeans-11.2.zip";
	String partFile = outputFile + ".part";
	
	// Fetch the public keys, that are considered trusted
	PGPPublicKeyRingCollection keyRings = fetchNetBeansReleaseKeyring(keysUrl);

	// Fetch the detached signature and convert it to a signature list
	PGPSignatureList p3;
	try (InputStream signatureStream = signatureUrl.openStream();
		InputStream decodedInputStream = PGPUtil.getDecoderStream(signatureStream)) {
	    JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(decodedInputStream);

	    Object o = pgpFact.nextObject();
	    if (o instanceof PGPCompressedData) {
		PGPCompressedData c1 = (PGPCompressedData) o;

		pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

		p3 = (PGPSignatureList) pgpFact.nextObject();
	    } else {
		p3 = (PGPSignatureList) o;
	    }
	}

	List<PGPPublicKey> publicKeys = new ArrayList<>();
	List<PGPSignature> signatures = new ArrayList<>();

	// For each signaure present in the signature list, the public key is
	// fetched from they public key file based on the keyID. With that key
	// the signature is initialized to begin the validation process
	//
	// After this loop exits, all signatures, for which a public key is
	// present in the downloaded public key list are initialized for validation.
	for (int i = 0; i < p3.size(); i++) {
	    PGPSignature sig = p3.get(0);
	    PGPPublicKey key = keyRings.getPublicKey(sig.getKeyID());
	    if (key != null) {
		sig.init(new BcPGPContentVerifierBuilderProvider(), key);
		publicKeys.add(key);
		signatures.add(sig);
	    }
	}

	// Download the file to a temp file (<targetfilename>.part)
	// While downloading the signatures are updated with the read data
	try (InputStream dataStream = downloadUrl.openStream();
		FileOutputStream fos = new FileOutputStream(partFile)) {
	    byte[] buffer = new byte[1024 * 1024];
	    int read;
	    while ((read = dataStream.read(buffer)) >= 0) {
		for (PGPSignature sig : signatures) {
		    sig.update(buffer, 0, read);
		}
		fos.write(buffer, 0, read);
	    }
	}

	// Finalize the signature verification process and output the verdict
	// to console
	boolean atLeastOneSuccessfulVerification = false;
	for (int i = 0; i < signatures.size(); i++) {
	    PGPSignature sig = signatures.get(i);
	    PGPPublicKey key = publicKeys.get(i);
	    System.out.println("---------------------------------------------------");
	    System.out.println("Fingerprint: " + hexEncode(key.getFingerprint()));
	    key.getUserIDs().forEachRemaining(uid -> System.out.println("UID:         " + uid));
	    if (sig.verify()) {
		atLeastOneSuccessfulVerification = true;
		System.out.println("  VERIFIED");
	    } else {
		System.out.println("  FAILED");
	    }
	    System.out.println("");
	}

	if(atLeastOneSuccessfulVerification) {
	    System.out.printf("Verifiation successful - copying '%s' to '%s'", partFile, outputFile);
	    Files.move(Path.of(partFile), Path.of(outputFile), StandardCopyOption.REPLACE_EXISTING);
	} else {
	    System.out.printf("Verifiation failed - deleting file (%s)", partFile);
	    Files.delete(Path.of(partFile));
	}
    }

    /**
     * Fetch the KEYS file from a save place. The KEYS file is parsed and the
     * key ring collection is returned to the caller.
     *
     * @param url download location of the KEYS file
     * @return key ring collection contained in the referenced file
     * @throws IOException
     * @throws MalformedURLException
     * @throws PGPException
     */
    private static PGPPublicKeyRingCollection fetchNetBeansReleaseKeyring(URL keysUrl) throws IOException, MalformedURLException, PGPException {
	List<PGPPublicKeyRing> keyRings = new ArrayList<>();

	KeyFingerPrintCalculator kfpc = new BcKeyFingerprintCalculator();

	// Open the input stream from the supplied URL
	try (InputStream is = keysUrl.openStream();
		BufferedInputStream bis = new BufferedInputStream(is)) {

	    // Per invokation of getDecoderStream/new PGPPublicKeyRing one
	    // PUBLIC KEY BLOCK is read. So iterate until the whole input
	    // stream is consumed
	    bis.mark(1);
	    while (bis.read() >= 0) {
		bis.reset();
		InputStream is2 = PGPUtil.getDecoderStream(bis);
		PGPPublicKeyRing keyRing = new PGPPublicKeyRing(is2, kfpc);
		keyRings.add(keyRing);
		bis.mark(1);
	    }
	}

	return new PGPPublicKeyRingCollection(keyRings);
    }

    /**
     * Encode a byte array to a hexencoded string, as is done by sha512sum and
     * similiar tools.
     *
     * @param input byte[] to encode
     * @return hex encoded string of the input byte[]
     */
    public static String hexEncode(byte[] input) {
	StringBuilder sb = new StringBuilder(input.length * 2);
	for (byte b : input) {
	    sb.append(Character.forDigit((b & 0xF0) >> 4, 16));
	    sb.append(Character.forDigit((b & 0x0F), 16));
	}
	return sb.toString();
    }
}
