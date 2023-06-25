import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.core.Transaction;
import org.ethereum.crypto.ECKey;
import org.ethereum.crypto.HashUtil;
import org.ethereum.facade.Ethereum;
import org.ethereum.listener.EthereumListenerAdapter;
import org.ethereum.util.ByteUtil;
import org.ethereum.vm.program.ProgramResult;
import org.spongycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

public class IoVDataAuthenticator {
    private Ethereum ethereum;
    private ECKey senderKey;
    private byte[] smartContractAddress;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public IoVDataAuthenticator(Ethereum ethereum, ECKey senderKey, byte[] smartContractAddress) {
        this.ethereum = ethereum;
        this.senderKey = senderKey;
        this.smartContractAddress = smartContractAddress;
        this.ethereum.addListener(new EthereumListenerAdapter() {
            // Add necessary listeners for events such as onTransactionExecuted, onBlock, etc.
        });
    }

    public void sendData(byte[] recipientAddress, byte[] data) {
        byte[] dataHash = hashData(data);
        byte[] signature = signData(dataHash, senderKey);

        // Create and send a transaction to the smart contract with the recipient's address, data, and signature
        byte[] txData = ByteUtil.merge(recipientAddress, data, signature);
        Transaction tx = new Transaction(null, null, null, smartContractAddress, null, txData);
        tx.sign(senderKey);
        ethereum.submitTransaction(tx);
    }

    private byte[] hashData(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(data);
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing data: " + e.getMessage());
        }
    }

    private byte[] signData(byte[] dataHash, ECKey privateKey) {
        ECKey.ECDSASignature signature = privateKey.sign(dataHash);
        return signature.toByteArray();
    }

    public boolean verifySignature(byte[] data, byte[] signatureBytes, byte[] publicKeyBytes) {
        byte[] dataHash = hashData(data);
        ECKey.ECDSASignature signature = ECKey.ECDSASignature.fromComponents(
                Arrays.copyOfRange(signatureBytes, 0, 32),
                Arrays.copyOfRange(signatureBytes, 32, 64),
                signatureBytes[64]
        );

        BigInteger recoveredPubKey = ECKey.signatureToKey(dataHash, signature);
        byte[] recoveredPubKeyBytes = ECKey.fromPublicOnly(recoveredPubKey).getPubKey();
        return Arrays.equals(recoveredPubKeyBytes, publicKeyBytes);
    }

    public byte[] getPublicKey(byte[] ethereumAddress) {
        // Call the smart contract function to retrieve the public key for the given Ethereum address
        byte[] functionSignature = HashUtil.sha3("getPublicKey(address)".getBytes());
        byte[] functionSelector = Arrays.copyOfRange(functionSignature, 0, 4);
        byte[] paddedAddress = ByteUtil.merge(new byte[12], ethereumAddress);
        byte[] callData = ByteUtil.merge(functionSelector, paddedAddress);

        ProgramResult result = ethereum.callConstantFunction(smartContractAddress, callData);
        return result.getHReturn();
    }
}
