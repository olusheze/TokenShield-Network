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

