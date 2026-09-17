package da.decentralized_authentication.Service;

public interface WalletService {
    String registerPublicKey(Long holderId, String username, String publicKeyJwk);
}