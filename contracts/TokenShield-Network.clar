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
