# ScamShield evaluation report

Generated 2026-09-25T06:57:48+00:00 - config `298d46e23d33de00` - thresholds MEDIUM >= 30, HIGH >= 55, CRITICAL >= 80.

Positive class = scam. **warn** = flagged at tier >= MEDIUM (any warning). **interrupt** = flagged at tier >= HIGH (links disabled). The dataset is synthetic; see LIMITATIONS.md.

## Summary

| Mode | Split | n | Op. point | Precision | Recall | F1 | FPR | TP | FP | TN | FN |
|---|---|---|---|---|---|---|---|---|---|---|---|
| rules | all | 79 | warn | 1.000 | 0.933 | 0.966 | 0.000 | 42 | 0 | 34 | 3 |
| rules | all | 79 | interrupt | 1.000 | 0.756 | 0.861 | 0.000 | 34 | 0 | 34 | 11 |
| rules | dev | 55 | warn | 1.000 | 0.970 | 0.985 | 0.000 | 32 | 0 | 22 | 1 |
| rules | dev | 55 | interrupt | 1.000 | 0.848 | 0.918 | 0.000 | 28 | 0 | 22 | 5 |
| rules | holdout | 24 | warn | 1.000 | 0.833 | 0.909 | 0.000 | 10 | 0 | 12 | 2 |
| rules | holdout | 24 | interrupt | 1.000 | 0.500 | 0.667 | 0.000 | 6 | 0 | 12 | 6 |
| image | all | 79 | warn | 1.000 | 0.911 | 0.953 | 0.000 | 41 | 0 | 34 | 4 |
| image | all | 79 | interrupt | 1.000 | 0.733 | 0.846 | 0.000 | 33 | 0 | 34 | 12 |
| image | dev | 55 | warn | 1.000 | 0.970 | 0.985 | 0.000 | 32 | 0 | 22 | 1 |
| image | dev | 55 | interrupt | 1.000 | 0.818 | 0.900 | 0.000 | 27 | 0 | 22 | 6 |
| image | holdout | 24 | warn | 1.000 | 0.750 | 0.857 | 0.000 | 9 | 0 | 12 | 3 |
| image | holdout | 24 | interrupt | 1.000 | 0.500 | 0.667 | 0.000 | 6 | 0 | 12 | 6 |
| hybrid | - | - | - | skipped: no Anthropic credentials (set ANTHROPIC_API_KEY in .env) | | | | | | | |

## rules

Latency per message: p50 **1.04 ms**, p95 **2.23 ms** (mean 1.17 ms). Cases marked needs_review: 0.

### Confusion matrix (label x tier)

| label \ tier | INSUFFICIENT | LOW | MEDIUM | HIGH | CRITICAL |
|---|---|---|---|---|---|
| scam | 0 | 3 | 8 | 15 | 19 |
| legit | 0 | 34 | 0 | 0 | 0 |

Binary confusion at the warn point:

| | predicted scam | predicted legit |
|---|---|---|
| actual scam | 42 | 3 |
| actual legit | 0 | 34 |

### Per category (warned / interrupted / n)

| category | warned | interrupted | n |
|---|---|---|---|
| legit:2fa_code_requested | 0 | 0 | 2 |
| legit:appointment_reminder | 0 | 0 | 1 |
| legit:bank_fraud_alert_genuine | 0 | 0 | 2 |
| legit:bank_low_balance | 0 | 0 | 1 |
| legit:building_notice | 0 | 0 | 1 |
| legit:colleague_urgent | 0 | 0 | 1 |
| legit:crypto_receipt | 0 | 0 | 1 |
| legit:delivery_notice_genuine | 0 | 0 | 2 |
| legit:email_verification | 0 | 0 | 1 |
| legit:family_money_request | 0 | 0 | 1 |
| legit:family_text | 0 | 0 | 1 |
| legit:friend_chat_crypto | 0 | 0 | 1 |
| legit:friend_money_request | 0 | 0 | 1 |
| legit:friend_new_number | 0 | 0 | 1 |
| legit:healthcare_portal | 0 | 0 | 1 |
| legit:it_notice | 0 | 0 | 1 |
| legit:medical_bill | 0 | 0 | 1 |
| legit:order_shipped | 0 | 0 | 1 |
| legit:password_reset_requested | 0 | 0 | 1 |
| legit:payment_receipt | 0 | 0 | 1 |
| legit:pharmacy | 0 | 0 | 1 |
| legit:recruiter_genuine | 0 | 0 | 3 |
| legit:retail_promo | 0 | 0 | 1 |
| legit:school_notice | 0 | 0 | 1 |
| legit:security_alert_genuine | 0 | 0 | 1 |
| legit:toll_statement | 0 | 0 | 1 |
| legit:utility_bill | 0 | 0 | 1 |
| legit:work_chat | 0 | 0 | 1 |
| legit:work_email | 0 | 0 | 1 |
| scam:account_phishing | 1 | 1 | 1 |
| scam:advance_fee | 1 | 1 | 1 |
| scam:adversarial_combined | 1 | 1 | 1 |
| scam:adversarial_homoglyph | 1 | 1 | 1 |
| scam:adversarial_leet_injection | 1 | 1 | 1 |
| scam:adversarial_math_letters | 1 | 1 | 1 |
| scam:adversarial_prompt_injection | 1 | 1 | 1 |
| scam:adversarial_zero_width | 1 | 1 | 1 |
| scam:bank_impersonation | 2 | 2 | 2 |
| scam:bank_impersonation_otp | 2 | 2 | 2 |
| scam:callback_phishing | 1 | 0 | 1 |
| scam:ceo_fraud | 2 | 2 | 2 |
| scam:credential_phishing_email | 1 | 1 | 1 |
| scam:crypto_exchange_phishing | 1 | 1 | 1 |
| scam:crypto_giveaway | 1 | 1 | 1 |
| scam:delivery_smishing | 2 | 2 | 2 |
| scam:fake_invoice_callback | 1 | 1 | 1 |
| scam:fake_job_check | 1 | 1 | 1 |
| scam:fake_recruiter | 1 | 0 | 1 |
| scam:family_new_number | 2 | 2 | 2 |
| scam:government_impersonation | 2 | 2 | 2 |
| scam:grandparent_scam | 1 | 1 | 1 |
| scam:investment_group | 1 | 0 | 1 |
| scam:llm_written_bec | 1 | 0 | 1 |
| scam:otp_harvesting | 2 | 1 | 2 |
| scam:password_expiry_phishing | 1 | 0 | 1 |
| scam:payment_redirection | 1 | 1 | 1 |
| scam:phishing_email | 1 | 1 | 1 |
| scam:prize_lottery | 1 | 0 | 1 |
| scam:rental_deposit | 1 | 1 | 1 |
| scam:romance_crypto | 1 | 1 | 1 |
| scam:romance_offplatform | 0 | 0 | 1 |
| scam:subscription_phishing | 1 | 1 | 1 |
| scam:task_job_scam | 1 | 0 | 1 |
| scam:tax_refund_phishing | 1 | 1 | 1 |
| scam:tech_support | 1 | 1 | 1 |
| scam:toll_smishing | 0 | 0 | 1 |
| scam:utility_disconnection | 0 | 0 | 1 |

### Error analysis (3 misclassification(s) at the warn point)

**d-s20** (dev, romance_offplatform) - false negative (no warning), tier LOW, score 15

> Hi handsome, I saw your profile and felt a connection 😊 I don't use this app much, can we talk on Telegram instead? My username is @lily_rose88

- Automated: Only R12:OFF_PLATFORM fired (score 15, 15 below MEDIUM). No credential/payment request or impersonation signal was matched, so the lure is invisible to the rules.
- Analysis: Early-stage romance lure: the only machine-visible signal is the move to Telegram (OFF_PLATFORM, 15). There is no request, link or impersonation yet - the ask comes days later. Rules alone cannot separate this from a friendly stranger; this is the case the LLM layer is for (flattery + unsolicited connection + platform switch). Deliberately not 'fixed' with a romance-opener keyword rule, which would be tuned to this one message.

**h-s01** (holdout, toll_smishing) - false negative (no warning), tier LOW, score 15

> E-ZPass: You have an unpaid toll of $6.89. To avoid a $50 late fee, settle your balance at https://ezpass-tollpay.top/pay today.

- Automated: Only R02:THREAT fired (score 15, 15 below MEDIUM). No credential/payment request or impersonation signal was matched, so the lure is invisible to the rules.
- Analysis: HOLDOUT - not tuned. Toll smishing for E-ZPass, which is not in the brand allowlist, so ezpass-tollpay.top is not a lookalike and no SENDER_MISMATCH can fire; 'late fee' is not in the UPFRONT_FEE lexicon; '.top' TLD reputation is not a signal. Fix candidates: add toll/utility brands to the allowlist, treat 'settle/pay your balance at <non-official link>' as a payment request, and add a TLD-risk signal. Illustrates the allowlist limitation in LIMITATIONS.md.

**h-s11** (holdout, utility_disconnection) - false negative (no warning), tier LOW, score 15

> FINAL NOTICE from City Power & Light: your electricity will be disconnected in 60 minutes due to an overdue balance. Pay now by calling [PHONE] - we accept Bitcoin or prepaid cards.

- Automated: Only R01:URGENCY fired (score 15, 15 below MEDIUM). No credential/payment request or impersonation signal was matched, so the lure is invisible to the rules.
- Analysis: HOLDOUT - not tuned. Two gaps: (1) the clause splitter breaks on ' - ', so 'Pay now by calling ...' and 'we accept Bitcoin or prepaid cards' land in different clauses and PAYMENT_METHOD (verb + term in one clause) never fires - a design bug found by the holdout; (2) 'will be disconnected' is not in the THREAT lexicon and 'City Power & Light' is not recognised as an authority, so CALLBACK_LURE is gated off. Fix candidates: pair payment verbs and terms across adjacent clauses, add service-disconnection threats, and treat unknown utility names in 'FINAL NOTICE from X' as authority claims.

Scams that were warned (MEDIUM) but not interrupted: d-s06 (fake_recruiter, 35), d-s12 (prize_lottery, 50), d-s13 (callback_phishing, 50), d-s28 (llm_written_bec, 30), h-s04 (task_job_scam, 35), h-s06 (password_expiry_phishing, 45), h-s07 (investment_group, 40), h-s09 (otp_harvesting, 30).


## image

Latency per message: p50 **10959.85 ms**, p95 **13683.97 ms** (mean 8678.66 ms). Cases marked needs_review: 0. Image mode: each message rendered as a phone screenshot, read by local OCR, no sender metadata; mean OCR word recall 0.984.

### Confusion matrix (label x tier)

| label \ tier | INSUFFICIENT | LOW | MEDIUM | HIGH | CRITICAL |
|---|---|---|---|---|---|
| scam | 0 | 4 | 8 | 17 | 16 |
| legit | 0 | 34 | 0 | 0 | 0 |

Binary confusion at the warn point:

| | predicted scam | predicted legit |
|---|---|---|
| actual scam | 41 | 4 |
| actual legit | 0 | 34 |

### Per category (warned / interrupted / n)

| category | warned | interrupted | n |
|---|---|---|---|
| legit:2fa_code_requested | 0 | 0 | 2 |
| legit:appointment_reminder | 0 | 0 | 1 |
| legit:bank_fraud_alert_genuine | 0 | 0 | 2 |
| legit:bank_low_balance | 0 | 0 | 1 |
| legit:building_notice | 0 | 0 | 1 |
| legit:colleague_urgent | 0 | 0 | 1 |
| legit:crypto_receipt | 0 | 0 | 1 |
| legit:delivery_notice_genuine | 0 | 0 | 2 |
| legit:email_verification | 0 | 0 | 1 |
| legit:family_money_request | 0 | 0 | 1 |
| legit:family_text | 0 | 0 | 1 |
| legit:friend_chat_crypto | 0 | 0 | 1 |
| legit:friend_money_request | 0 | 0 | 1 |
| legit:friend_new_number | 0 | 0 | 1 |
| legit:healthcare_portal | 0 | 0 | 1 |
| legit:it_notice | 0 | 0 | 1 |
| legit:medical_bill | 0 | 0 | 1 |
| legit:order_shipped | 0 | 0 | 1 |
| legit:password_reset_requested | 0 | 0 | 1 |
| legit:payment_receipt | 0 | 0 | 1 |
| legit:pharmacy | 0 | 0 | 1 |
| legit:recruiter_genuine | 0 | 0 | 3 |
| legit:retail_promo | 0 | 0 | 1 |
| legit:school_notice | 0 | 0 | 1 |
| legit:security_alert_genuine | 0 | 0 | 1 |
| legit:toll_statement | 0 | 0 | 1 |
| legit:utility_bill | 0 | 0 | 1 |
| legit:work_chat | 0 | 0 | 1 |
| legit:work_email | 0 | 0 | 1 |
| scam:account_phishing | 1 | 1 | 1 |
| scam:advance_fee | 1 | 1 | 1 |
| scam:adversarial_combined | 1 | 1 | 1 |
| scam:adversarial_homoglyph | 1 | 1 | 1 |
| scam:adversarial_leet_injection | 1 | 1 | 1 |
| scam:adversarial_math_letters | 1 | 1 | 1 |
| scam:adversarial_prompt_injection | 1 | 1 | 1 |
| scam:adversarial_zero_width | 1 | 1 | 1 |
| scam:bank_impersonation | 2 | 2 | 2 |
| scam:bank_impersonation_otp | 2 | 2 | 2 |
| scam:callback_phishing | 1 | 0 | 1 |
| scam:ceo_fraud | 2 | 2 | 2 |
| scam:credential_phishing_email | 1 | 1 | 1 |
| scam:crypto_exchange_phishing | 1 | 1 | 1 |
| scam:crypto_giveaway | 1 | 1 | 1 |
| scam:delivery_smishing | 2 | 2 | 2 |
| scam:fake_invoice_callback | 1 | 1 | 1 |
| scam:fake_job_check | 1 | 1 | 1 |
| scam:fake_recruiter | 1 | 0 | 1 |
| scam:family_new_number | 2 | 2 | 2 |
| scam:government_impersonation | 2 | 2 | 2 |
| scam:grandparent_scam | 1 | 1 | 1 |
| scam:investment_group | 1 | 0 | 1 |
| scam:llm_written_bec | 1 | 0 | 1 |
| scam:otp_harvesting | 2 | 1 | 2 |
| scam:password_expiry_phishing | 0 | 0 | 1 |
| scam:payment_redirection | 1 | 0 | 1 |
| scam:phishing_email | 1 | 1 | 1 |
| scam:prize_lottery | 1 | 0 | 1 |
| scam:rental_deposit | 1 | 1 | 1 |
| scam:romance_crypto | 1 | 1 | 1 |
| scam:romance_offplatform | 0 | 0 | 1 |
| scam:subscription_phishing | 1 | 1 | 1 |
| scam:task_job_scam | 1 | 0 | 1 |
| scam:tax_refund_phishing | 1 | 1 | 1 |
| scam:tech_support | 1 | 1 | 1 |
| scam:toll_smishing | 0 | 0 | 1 |
| scam:utility_disconnection | 0 | 0 | 1 |

### Error analysis (4 misclassification(s) at the warn point)

**d-s20** (dev, romance_offplatform) - false negative (no warning), tier LOW, score 15

> Hi handsome, I saw your profile and felt a connection 😊 I don't use this app much, can we talk on Telegram instead? My username is @lily_rose88

- Automated: Only R12:OFF_PLATFORM fired (score 15, 15 below MEDIUM). No credential/payment request or impersonation signal was matched, so the lure is invisible to the rules.
- Analysis: Early-stage romance lure: the only machine-visible signal is the move to Telegram (OFF_PLATFORM, 15). There is no request, link or impersonation yet - the ask comes days later. Rules alone cannot separate this from a friendly stranger; this is the case the LLM layer is for (flattery + unsolicited connection + platform switch). Deliberately not 'fixed' with a romance-opener keyword rule, which would be tuned to this one message.

**h-s01** (holdout, toll_smishing) - false negative (no warning), tier LOW, score 15

> E-ZPass: You have an unpaid toll of $6.89. To avoid a $50 late fee, settle your balance at https://ezpass-tollpay.top/pay today.

- Automated: Only R02:THREAT fired (score 15, 15 below MEDIUM). No credential/payment request or impersonation signal was matched, so the lure is invisible to the rules.
- Analysis: HOLDOUT - not tuned. Toll smishing for E-ZPass, which is not in the brand allowlist, so ezpass-tollpay.top is not a lookalike and no SENDER_MISMATCH can fire; 'late fee' is not in the UPFRONT_FEE lexicon; '.top' TLD reputation is not a signal. Fix candidates: add toll/utility brands to the allowlist, treat 'settle/pay your balance at <non-official link>' as a payment request, and add a TLD-risk signal. Illustrates the allowlist limitation in LIMITATIONS.md.

**h-s06** (holdout, password_expiry_phishing) - false negative (no warning), tier LOW, score 15

> Your password expires in 24 hours. Keep your current password by verifying here: https://outlook-keep-password.web.app

- Automated: Only R01:URGENCY fired (score 15, 15 below MEDIUM). No credential/payment request or impersonation signal was matched, so the lure is invisible to the rules.
- Analysis: Image mode only (text mode: MEDIUM). The 'Microsoft account team' identity exists only in the claimed-sender metadata, which a screenshot does not carry, and the link host outlook-keep-password.web.app is not matched because 'outlook' is a Microsoft product alias, not the brand key. Typing the claimed sender after upload restores SENDER_MISMATCH. Also shows the brand-key-only lookalike limitation.

**h-s11** (holdout, utility_disconnection) - false negative (no warning), tier LOW, score 15

> FINAL NOTICE from City Power & Light: your electricity will be disconnected in 60 minutes due to an overdue balance. Pay now by calling [PHONE] - we accept Bitcoin or prepaid cards.

- Automated: Only R01:URGENCY fired (score 15, 15 below MEDIUM). No credential/payment request or impersonation signal was matched, so the lure is invisible to the rules.
- Analysis: HOLDOUT - not tuned. Two gaps: (1) the clause splitter breaks on ' - ', so 'Pay now by calling ...' and 'we accept Bitcoin or prepaid cards' land in different clauses and PAYMENT_METHOD (verb + term in one clause) never fires - a design bug found by the holdout; (2) 'will be disconnected' is not in the THREAT lexicon and 'City Power & Light' is not recognised as an authority, so CALLBACK_LURE is gated off. Fix candidates: pair payment verbs and terms across adjacent clauses, add service-disconnection threats, and treat unknown utility names in 'FINAL NOTICE from X' as authority claims.

Scams that were warned (MEDIUM) but not interrupted: d-s06 (fake_recruiter, 35), d-s10 (payment_redirection, 50), d-s12 (prize_lottery, 50), d-s13 (callback_phishing, 50), d-s28 (llm_written_bec, 30), h-s04 (task_job_scam, 35), h-s07 (investment_group, 40), h-s09 (otp_harvesting, 30).

