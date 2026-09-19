package da.decentralized_authentication.Model.Enum;

public enum VerificationResult {
    SUCCESS,
    WRONG_CODE,
    EXPIRED,
    LOCKED,
    NOT_FOUND,
    USERNAME_TAKEN,
    EMAIL_TAKEN
}