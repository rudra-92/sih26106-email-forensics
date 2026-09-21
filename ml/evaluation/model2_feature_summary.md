# Model 2 — Forensic Feature Quality Audit Summary

- **Total Records Processed**: 11,338
- **Total Forensic Features**: 140
- **Processing Time**: 297.79 seconds

## Constant & Near-Constant Feature Checks

- **Constant Features (79)**: nlp_prob_spam, has_reply_to, from_replyto_mismatch, sender_domain_replyto_domain_mismatch, display_name_email_mismatch, multiple_reply_to_addresses, missing_message_id, cc_address_count, spf_present, spf_pass, spf_fail, spf_softfail, spf_neutral, spf_none, dkim_present, dkim_pass, dkim_fail, dmarc_present, dmarc_pass, dmarc_fail, dmarc_policy_none, dmarc_policy_quarantine, dmarc_policy_reject, spf_alignment_issue, dkim_alignment_issue, dmarc_alignment_issue, authentication_failure_count, received_hop_count, invalid_ip_count, hostname_ip_mismatch_count, timestamp_order_anomaly, subdomain_depth, punycode_flag, suspicious_tld_candidate, homoglyph_candidate, domain_mismatch, has_punycode, has_unicode_domain, html_present, plain_text_present, html_to_text_ratio, attachment_count, has_attachment, total_attachment_size_bytes, double_extension, executable_attachment, script_attachment, archive_attachment, document_attachment, macro_capable_document, MIME_extension_mismatch, file_entropy, printable_string_count, url_string_count, ip_string_count, email_string_count, is_pe, pe_entropy, section_count, suspicious_section_count, import_count, dll_count, export_count, pe_process_creation_apis, pe_command_execution_apis, pe_network_communication_apis, pe_memory_manipulation_apis, pe_persistence_apis, pe_credential_access_apis, has_macro, macro_count, embedded_object_count, suspicious_macro_indicator, pdf_has_javascript, pdf_has_openaction, pdf_has_launch, pdf_has_embedded_file, pdf_has_acroform, yara_match_count
- **Near-Constant Features (>99.9% same value) (19)**: display_name_present, multiple_from_addresses, missing_to, to_address_count, reserved_ip_count, has_ipv6, domain_length, hyphen_count, digit_count, special_character_count, unicode_flag, lookalike_domain_candidate, target_domain_min_distance_ratio, ip_based_url_count, has_ip_as_hostname, has_suspicious_tld_candidate, payment_request_present, credential_request_present, gift_card_request_present

## High Pairwise Correlations (> 0.98)

| Feature 1 | Feature 2 | Correlation |
| :--- | :--- | :---: |
| `missing_to` | `to_address_count` | 1.0 |
| `unique_ip_count` | `public_ip_count` | 0.9979 |
| `unique_ip_count` | `ip_count` | 1.0 |
| `public_ip_count` | `ip_count` | 0.9979 |
| `reserved_ip_count` | `has_ipv6` | 1.0 |
| `hyphen_count` | `digit_count` | 1.0 |
| `url_count` | `unique_url_count` | 1.0 |
| `body_length` | `word_count` | 0.9971 |
| feature_name                          | dtype   |   missing_percentage |   unique_values |      min |      max |     mean |      std |
|:--------------------------------------|:--------|---------------------:|----------------:|---------:|---------:|---------:|---------:|
| nlp_prob_legitimate                   | float64 |                    0 |            2182 |   0      |   0.9969 |   0.5579 |   0.4645 |
| nlp_prob_spam                         | float64 |                    0 |               1 |   0      |   0      |   0      |   0      |
| nlp_prob_phishing                     | float64 |                    0 |            1777 |   0.0005 |   0.9999 |   0.1494 |   0.3246 |
| nlp_prob_fraud                        | float64 |                    0 |            1588 |   0.0001 |   0.9993 |   0.2928 |   0.4341 |
| has_reply_to                          | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| from_replyto_mismatch                 | float64 |                  100 |               0 | nan      | nan      | nan      | nan      |
| sender_domain_replyto_domain_mismatch | float64 |                  100 |               0 | nan      | nan      | nan      | nan      |
| display_name_present                  | int64   |                    0 |               2 |   0      |   1      |   0.0002 |   0.0133 |
| display_name_email_mismatch           | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| multiple_from_addresses               | int64   |                    0 |               2 |   0      |   1      |   0.0005 |   0.023  |
| multiple_reply_to_addresses           | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| missing_message_id                    | int64   |                    0 |               1 |   1      |   1      |   1      |   0      |
| missing_date                          | int64   |                    0 |               2 |   0      |   1      |   0.9959 |   0.0643 |
| missing_from                          | int64   |                    0 |               2 |   0      |   1      |   0.9892 |   0.1032 |
| missing_to                            | int64   |                    0 |               2 |   0      |   1      |   0.9998 |   0.0133 |
| to_address_count                      | int64   |                    0 |               2 |   0      |   1      |   0.0002 |   0.0133 |
| cc_address_count                      | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| spf_present                           | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| spf_pass                              | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| spf_fail                              | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| spf_softfail                          | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| spf_neutral                           | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| spf_none                              | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| dkim_present                          | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| dkim_pass                             | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| dkim_fail                             | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| dmarc_present                         | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| dmarc_pass                            | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| dmarc_fail                            | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| dmarc_policy_none                     | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| dmarc_policy_quarantine               | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| dmarc_policy_reject                   | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| spf_alignment_issue                   | float64 |                  100 |               0 | nan      | nan      | nan      | nan      |
| dkim_alignment_issue                  | float64 |                  100 |               0 | nan      | nan      | nan      | nan      |
| dmarc_alignment_issue                 | float64 |                  100 |               0 | nan      | nan      | nan      | nan      |
| authentication_failure_count          | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| received_hop_count                    | int64   |                    0 |               1 |   0      |   0      |   0      |   0      |
| unique_ip_count                       | int64   |                    0 |              22 |   0      | 119      |   0.1088 |   2.489  |
| public_ip_count                       | int64   |                    0 |              22 |   0      | 118      |   0.097  |   2.4405 |
| private_ip_count                      | int64   |                    0 |               5 |   0      |   5      |   0.0056 |   0.1094 |
