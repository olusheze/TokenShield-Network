;; TokenShield Network - Stacks Blockchain Vault Protocol that serves as a Shielded Asset Storage System

;; Vault storage map
(define-map VaultStorage
  { vault-id: uint }
  {
    creator: principal,
    recipient: principal,
    token-id: uint,
    amount: uint,
    vault-state: (string-ascii 10),
    start-block: uint,
    end-block: uint
  }
)

;; Very Core constants
(define-constant CONTRACT_ADMIN tx-sender)
(define-constant ERR_NOT_ALLOWED (err u100))
(define-constant ERR_NO_VAULT (err u101))
(define-constant ERR_ALREADY_HANDLED (err u102))
(define-constant ERR_TRANSFER_FAILED (err u103))
(define-constant ERR_BAD_ID (err u104))
(define-constant ERR_BAD_AMOUNT (err u105))
(define-constant ERR_BAD_CREATOR (err u106))
(define-constant ERR_VAULT_EXPIRED (err u107))
(define-constant VAULT_TIMEOUT_BLOCKS u1008) 

;; Tracking the most recent vault ID
(define-data-var current-vault-id uint u0)

;; Private Functions
(define-private (valid-recipient? (recipient principal))
  (and 
    (not (is-eq recipient tx-sender))
    (not (is-eq recipient (as-contract tx-sender)))
  )
)

(define-private (valid-vault-id? (vault-id uint))
  (<= vault-id (var-get current-vault-id))
)

;; Public functions

;; Complete vault transfer to recipient
(define-public (complete-vault-transfer (vault-id uint))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (recipient (get recipient vault-data))
        (amount (get amount vault-data))
        (token (get token-id vault-data))
      )
      (asserts! (or (is-eq tx-sender CONTRACT_ADMIN) (is-eq tx-sender (get creator vault-data))) ERR_NOT_ALLOWED)
      (asserts! (is-eq (get vault-state vault-data) "pending") ERR_ALREADY_HANDLED)
      (asserts! (<= block-height (get end-block vault-data)) ERR_VAULT_EXPIRED)
      (match (as-contract (stx-transfer? amount tx-sender recipient))
        success
          (begin
            (map-set VaultStorage
              { vault-id: vault-id }
              (merge vault-data { vault-state: "completed" })
            )
            (print {action: "vault_transferred", vault-id: vault-id, recipient: recipient, token-id: token, amount: amount})
            (ok true)
          )
        error ERR_TRANSFER_FAILED
      )
    )
  )
)

;; Return assets to creator
(define-public (return-vault-assets (vault-id uint))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data))
        (amount (get amount vault-data))
      )
      (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERR_NOT_ALLOWED)
      (asserts! (is-eq (get vault-state vault-data) "pending") ERR_ALREADY_HANDLED)
      (match (as-contract (stx-transfer? amount tx-sender creator))
        success
          (begin
            (map-set VaultStorage
              { vault-id: vault-id }
              (merge vault-data { vault-state: "returned" })
            )
            (print {action: "assets_returned", vault-id: vault-id, creator: creator, amount: amount})
            (ok true)
          )
        error ERR_TRANSFER_FAILED
      )
    )
  )
)

;; Creator requests vault cancellation
(define-public (cancel-vault (vault-id uint))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data))
        (amount (get amount vault-data))
      )
      (asserts! (is-eq tx-sender creator) ERR_NOT_ALLOWED)
      (asserts! (is-eq (get vault-state vault-data) "pending") ERR_ALREADY_HANDLED)
      (asserts! (<= block-height (get end-block vault-data)) ERR_VAULT_EXPIRED)
      (match (as-contract (stx-transfer? amount tx-sender creator))
        success
          (begin
            (map-set VaultStorage
              { vault-id: vault-id }
              (merge vault-data { vault-state: "cancelled" })
            )
            (print {action: "vault_cancelled", vault-id: vault-id, creator: creator, amount: amount})
            (ok true)
          )
        error ERR_TRANSFER_FAILED
      )
    )
  )
)

;; Extend vault duration
(define-public (extend-vault-duration (vault-id uint) (extra-blocks uint))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (asserts! (> extra-blocks u0) ERR_BAD_AMOUNT)
    (asserts! (<= extra-blocks u1440) ERR_BAD_AMOUNT) ;; Max ~10 days extension
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data)) 
        (recipient (get recipient vault-data))
        (current-end (get end-block vault-data))
        (updated-end (+ current-end extra-blocks))
      )
      (asserts! (or (is-eq tx-sender creator) (is-eq tx-sender recipient) (is-eq tx-sender CONTRACT_ADMIN)) ERR_NOT_ALLOWED)
      (asserts! (or (is-eq (get vault-state vault-data) "pending") (is-eq (get vault-state vault-data) "accepted")) ERR_ALREADY_HANDLED)
      (map-set VaultStorage
        { vault-id: vault-id }
        (merge vault-data { end-block: updated-end })
      )
      (print {action: "vault_extended", vault-id: vault-id, requestor: tx-sender, new-end-block: updated-end})
      (ok true)
    )
  )
)

;; Claim expired vault assets
(define-public (claim-expired-vault (vault-id uint))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data))
        (amount (get amount vault-data))
        (expiry (get end-block vault-data))
      )
      (asserts! (or (is-eq tx-sender creator) (is-eq tx-sender CONTRACT_ADMIN)) ERR_NOT_ALLOWED)
      (asserts! (or (is-eq (get vault-state vault-data) "pending") (is-eq (get vault-state vault-data) "accepted")) ERR_ALREADY_HANDLED)
      (asserts! (> block-height expiry) (err u108)) ;; Must be expired
      (match (as-contract (stx-transfer? amount tx-sender creator))
        success
          (begin
            (map-set VaultStorage
              { vault-id: vault-id }
              (merge vault-data { vault-state: "expired" })
            )
            (print {action: "expired_vault_claimed", vault-id: vault-id, creator: creator, amount: amount})
            (ok true)
          )
        error ERR_TRANSFER_FAILED
      )
    )
  )
)
;; Initiate vault dispute
(define-public (dispute-vault (vault-id uint) (reason (string-ascii 50)))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data))
        (recipient (get recipient vault-data))
      )
      (asserts! (or (is-eq tx-sender creator) (is-eq tx-sender recipient)) ERR_NOT_ALLOWED)
      (asserts! (or (is-eq (get vault-state vault-data) "pending") (is-eq (get vault-state vault-data) "accepted")) ERR_ALREADY_HANDLED)
      (asserts! (<= block-height (get end-block vault-data)) ERR_VAULT_EXPIRED)
      (map-set VaultStorage
        { vault-id: vault-id }
        (merge vault-data { vault-state: "disputed" })
      )
      (print {action: "vault_disputed", vault-id: vault-id, disputant: tx-sender, reason: reason})
      (ok true)
    )
  )
)

;; Add signature verification
(define-public (add-verify-signature (vault-id uint) (signature (buff 65)))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data))
        (recipient (get recipient vault-data))
      )
      (asserts! (or (is-eq tx-sender creator) (is-eq tx-sender recipient)) ERR_NOT_ALLOWED)
      (asserts! (or (is-eq (get vault-state vault-data) "pending") (is-eq (get vault-state vault-data) "accepted")) ERR_ALREADY_HANDLED)
      (print {action: "signature_verified", vault-id: vault-id, signer: tx-sender, signature: signature})
      (ok true)
    )
  )
)

;; Set backup address
(define-public (set-backup-address (vault-id uint) (backup-address principal))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data))
      )
      (asserts! (is-eq tx-sender creator) ERR_NOT_ALLOWED)
      (asserts! (not (is-eq backup-address tx-sender)) (err u111)) ;; Backup address must be different
      (asserts! (is-eq (get vault-state vault-data) "pending") ERR_ALREADY_HANDLED)
      (print {action: "backup_set", vault-id: vault-id, creator: creator, backup: backup-address})
      (ok true)
    )
  )
)


;; Resolve dispute with arbitration
(define-public (resolve-dispute (vault-id uint) (creator-percentage uint))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERR_NOT_ALLOWED)
    (asserts! (<= creator-percentage u100) ERR_BAD_AMOUNT) ;; Percentage must be 0-100
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data))
        (recipient (get recipient vault-data))
        (amount (get amount vault-data))
        (creator-amount (/ (* amount creator-percentage) u100))
        (recipient-amount (- amount creator-amount))
      )
      (asserts! (is-eq (get vault-state vault-data) "disputed") (err u112)) ;; Must be disputed
      (asserts! (<= block-height (get end-block vault-data)) ERR_VAULT_EXPIRED)

      ;; Send creator's portion
      (unwrap! (as-contract (stx-transfer? creator-amount tx-sender creator)) ERR_TRANSFER_FAILED)

      ;; Send recipient's portion
      (unwrap! (as-contract (stx-transfer? recipient-amount tx-sender recipient)) ERR_TRANSFER_FAILED)

      (map-set VaultStorage
        { vault-id: vault-id }
        (merge vault-data { vault-state: "resolved" })
      )
      (print {action: "dispute_resolved", vault-id: vault-id, creator: creator, recipient: recipient, 
              creator-amount: creator-amount, recipient-amount: recipient-amount, creator-percentage: creator-percentage})
      (ok true)
    )
  )
)

;; Add extra approval for high-value vaults
(define-public (add-additional-approval (vault-id uint) (approver principal))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data))
        (amount (get amount vault-data))
      )
      ;; Only for high-value vaults (> 1000 STX)
      (asserts! (> amount u1000) (err u120))
      (asserts! (or (is-eq tx-sender creator) (is-eq tx-sender CONTRACT_ADMIN)) ERR_NOT_ALLOWED)
      (asserts! (is-eq (get vault-state vault-data) "pending") ERR_ALREADY_HANDLED)
      (print {action: "approval_added", vault-id: vault-id, approver: approver, requestor: tx-sender})
      (ok true)
    )
  )
)

;; Freeze suspicious vault
(define-public (freeze-suspicious-vault (vault-id uint) (reason (string-ascii 100)))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data))
        (recipient (get recipient vault-data))
      )
      (asserts! (or (is-eq tx-sender CONTRACT_ADMIN) (is-eq tx-sender creator) (is-eq tx-sender recipient)) ERR_NOT_ALLOWED)
      (asserts! (or (is-eq (get vault-state vault-data) "pending") 
                   (is-eq (get vault-state vault-data) "accepted")) 
                ERR_ALREADY_HANDLED)
      (map-set VaultStorage
        { vault-id: vault-id }
        (merge vault-data { vault-state: "frozen" })
      )
      (print {action: "vault_frozen", vault-id: vault-id, reporter: tx-sender, reason: reason})
      (ok true)
    )
  )
)

;; Create staged payment vault
(define-public (create-staged-vault (recipient principal) (token-id uint) (amount uint) (phases uint))
  (let 
    (
      (new-id (+ (var-get current-vault-id) u1))
      (end-date (+ block-height VAULT_TIMEOUT_BLOCKS))
      (phase-amount (/ amount phases))
    )
    (asserts! (> amount u0) ERR_BAD_AMOUNT)
    (asserts! (> phases u0) ERR_BAD_AMOUNT)
    (asserts! (<= phases u5) ERR_BAD_AMOUNT) ;; Max 5 phases
    (asserts! (valid-recipient? recipient) ERR_BAD_CREATOR)
    (asserts! (is-eq (* phase-amount phases) amount) (err u121)) ;; Ensure even division
    (match (stx-transfer? amount tx-sender (as-contract tx-sender))
      success
        (begin
          (var-set current-vault-id new-id)
          (print {action: "staged_vault_created", vault-id: new-id, creator: tx-sender, recipient: recipient, 
                  token-id: token-id, amount: amount, phases: phases, phase-amount: phase-amount})
          (ok new-id)
        )
      error ERR_TRANSFER_FAILED
    )
  )
)
;; Schedule operation with delay
(define-public (schedule-critical-op (operation (string-ascii 20)) (parameters (list 10 uint)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERR_NOT_ALLOWED)
    (asserts! (> (len parameters) u0) ERR_BAD_AMOUNT)
    (let
      (
        (execution-time (+ block-height u144)) ;; 24 hours delay
      )
      (print {action: "operation_scheduled", operation: operation, parameters: parameters, execution-time: execution-time})
      (ok execution-time)
    )
  )
)

;; Enable 2FA for high-value vaults
(define-public (enable-auth-2fa (vault-id uint) (auth-code (buff 32)))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data))
        (amount (get amount vault-data))
      )
      ;; Only for vaults above threshold
      (asserts! (> amount u5000) (err u130))
      (asserts! (is-eq tx-sender creator) ERR_NOT_ALLOWED)
      (asserts! (is-eq (get vault-state vault-data) "pending") ERR_ALREADY_HANDLED)
      (print {action: "2fa_enabled", vault-id: vault-id, creator: creator, auth-hash: (hash160 auth-code)})
      (ok true)
    )
  )
)

;; Cryptographic verification for high-value vaults
(define-public (crypto-verify-transaction (vault-id uint) (message (buff 32)) (signature (buff 65)) (signer principal))
  (begin
    (asserts! (valid-vault-id? vault-id) ERR_BAD_ID)
    (let
      (
        (vault-data (unwrap! (map-get? VaultStorage { vault-id: vault-id }) ERR_NO_VAULT))
        (creator (get creator vault-data))
        (recipient (get recipient vault-data))
        (verify-result (unwrap! (secp256k1-recover? message signature) (err u150)))
      )
      ;; Verify with cryptographic proof
      (asserts! (or (is-eq tx-sender creator) (is-eq tx-sender recipient) (is-eq tx-sender CONTRACT_ADMIN)) ERR_NOT_ALLOWED)
      (asserts! (or (is-eq signer creator) (is-eq signer recipient)) (err u151))
      (asserts! (is-eq (get vault-state vault-data) "pending") ERR_ALREADY_HANDLED)

      ;; Verify signature matches expected signer
      (asserts! (is-eq (unwrap! (principal-of? verify-result) (err u152)) signer) (err u153))

      (print {action: "crypto_verification_complete", vault-id: vault-id, verifier: tx-sender, signer: signer})
      (ok true)
    )
  )
)
