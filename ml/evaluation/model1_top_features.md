# SIH26106 — Model 1 Top Predictive Features (Interpretability)

> [!NOTE]
> In a cybersecurity context, these weights reflect statistical associations learned from the TF-IDF representations. They represent **model features**, not forensic proof that any specific word proves an email is malicious.

## Class: `fraud_related`

| Rank | Feature / N-gram | Logistic Regression Coefficient | Threat Interpretation |
| :---: | :--- | :---: | :--- |
| 1 | `my` | **+2.8419** | Advance-fee scam financial/contract narrative markers |
| 2 | `me` | **+2.2378** | Advance-fee scam financial/contract narrative markers |
| 3 | `money` | **+2.1664** | Advance-fee scam financial/contract narrative markers |
| 4 | `mr` | **+1.8900** | Advance-fee scam financial/contract narrative markers |
| 5 | `bank` | **+1.8838** | Advance-fee scam financial/contract narrative markers |
| 6 | `am` | **+1.8711** | Advance-fee scam financial/contract narrative markers |
| 7 | `funds` | **+1.6938** | Advance-fee scam financial/contract narrative markers |
| 8 | `country` | **+1.6082** | Advance-fee scam financial/contract narrative markers |
| 9 | `fund` | **+1.5281** | Advance-fee scam financial/contract narrative markers |
| 10 | `million` | **+1.5076** | Advance-fee scam financial/contract narrative markers |
| 11 | `will` | **+1.4875** | Advance-fee scam financial/contract narrative markers |
| 12 | `us` | **+1.4854** | Advance-fee scam financial/contract narrative markers |
| 13 | `as` | **+1.4744** | Advance-fee scam financial/contract narrative markers |
| 14 | `of` | **+1.4694** | Advance-fee scam financial/contract narrative markers |
| 15 | `business` | **+1.4243** | Advance-fee scam financial/contract narrative markers |
| 16 | `dollars` | **+1.4102** | Advance-fee scam financial/contract narrative markers |
| 17 | `company` | **+1.3891** | Advance-fee scam financial/contract narrative markers |
| 18 | `his` | **+1.3875** | Advance-fee scam financial/contract narrative markers |
| 19 | `transaction` | **+1.3852** | Advance-fee scam financial/contract narrative markers |
| 20 | `to you` | **+1.3483** | Advance-fee scam financial/contract narrative markers |
| 21 | `yahoo` | **+1.2954** | Advance-fee scam financial/contract narrative markers |
| 22 | `of the` | **+1.2920** | Advance-fee scam financial/contract narrative markers |
| 23 | `000` | **+1.2586** | Advance-fee scam financial/contract narrative markers |
| 24 | `name` | **+1.2413** | Advance-fee scam financial/contract narrative markers |
| 25 | `investment` | **+1.2408** | Advance-fee scam financial/contract narrative markers |
| 26 | `the money` | **+1.2263** | Advance-fee scam financial/contract narrative markers |
| 27 | `your` | **+1.2230** | Advance-fee scam financial/contract narrative markers |
| 28 | `assistance` | **+1.2132** | Advance-fee scam financial/contract narrative markers |
| 29 | `sum` | **+1.1894** | Advance-fee scam financial/contract narrative markers |
| 30 | `of my` | **+1.1832** | Advance-fee scam financial/contract narrative markers |

---

## Class: `legitimate`

| Rank | Feature / N-gram | Logistic Regression Coefficient | Threat Interpretation |
| :---: | :--- | :---: | :--- |
| 1 | `enron` | **+1.8465** | Legitimate organizational/communication terminology |
| 2 | `http` | **+1.5127** | Legitimate organizational/communication terminology |
| 3 | `wrote` | **+1.4503** | Legitimate organizational/communication terminology |
| 4 | `2007` | **+1.3918** | Legitimate organizational/communication terminology |
| 5 | `the` | **+1.3720** | Legitimate organizational/communication terminology |
| 6 | `at` | **+1.3264** | Legitimate organizational/communication terminology |
| 7 | `list` | **+1.2180** | Legitimate organizational/communication terminology |
| 8 | `unsubscribe` | **+1.1296** | Legitimate organizational/communication terminology |
| 9 | `re` | **+1.1151** | Legitimate organizational/communication terminology |
| 10 | `edu` | **+1.0663** | Legitimate organizational/communication terminology |
| 11 | `http www` | **+1.0462** | Legitimate organizational/communication terminology |
| 12 | `2008` | **+0.9672** | Legitimate organizational/communication terminology |
| 13 | `www` | **+0.9511** | Legitimate organizational/communication terminology |
| 14 | `it` | **+0.9493** | Legitimate organizational/communication terminology |
| 15 | `there` | **+0.9433** | Legitimate organizational/communication terminology |
| 16 | `perl` | **+0.9409** | Legitimate organizational/communication terminology |
| 17 | `but` | **+0.8938** | Legitimate organizational/communication terminology |
| 18 | `university` | **+0.8577** | Legitimate organizational/communication terminology |
| 19 | `what` | **+0.8300** | Legitimate organizational/communication terminology |
| 20 | `pm` | **+0.8204** | Legitimate organizational/communication terminology |
| 21 | `2000` | **+0.7959** | Legitimate organizational/communication terminology |
| 22 | `html` | **+0.7943** | Legitimate organizational/communication terminology |
| 23 | `to unsubscribe` | **+0.7788** | Legitimate organizational/communication terminology |
| 24 | `like` | **+0.7649** | Legitimate organizational/communication terminology |
| 25 | `thanks` | **+0.7586** | Legitimate organizational/communication terminology |
| 26 | `2001` | **+0.7567** | Legitimate organizational/communication terminology |
| 27 | `vince` | **+0.7521** | Legitimate organizational/communication terminology |
| 28 | `see` | **+0.7510** | Legitimate organizational/communication terminology |
| 29 | `subject` | **+0.7471** | Legitimate organizational/communication terminology |
| 30 | `week` | **+0.7463** | Legitimate organizational/communication terminology |

---

## Class: `phishing`

| Rank | Feature / N-gram | Logistic Regression Coefficient | Threat Interpretation |
| :---: | :--- | :---: | :--- |
| 1 | `account` | **+3.1431** | Urgency, credential harvesting, account verification markers |
| 2 | `your` | **+3.0167** | Urgency, credential harvesting, account verification markers |
| 3 | `monkey` | **+2.9335** | Urgency, credential harvesting, account verification markers |
| 4 | `jose` | **+2.9097** | Urgency, credential harvesting, account verification markers |
| 5 | `monkey org` | **+2.8489** | Urgency, credential harvesting, account verification markers |
| 6 | `your account` | **+2.6967** | Urgency, credential harvesting, account verification markers |
| 7 | `jose monkey` | **+2.3041** | Urgency, credential harvesting, account verification markers |
| 8 | `click` | **+2.1798** | Urgency, credential harvesting, account verification markers |
| 9 | `update` | **+2.1531** | Urgency, credential harvesting, account verification markers |
| 10 | `utf` | **+1.9650** | Urgency, credential harvesting, account verification markers |
| 11 | `usaa` | **+1.7113** | Urgency, credential harvesting, account verification markers |
| 12 | `view` | **+1.7101** | Urgency, credential harvesting, account verification markers |
| 13 | `paypal` | **+1.6277** | Urgency, credential harvesting, account verification markers |
| 14 | `customer` | **+1.5585** | Urgency, credential harvesting, account verification markers |
| 15 | `2016` | **+1.5466** | Urgency, credential harvesting, account verification markers |
| 16 | `payment` | **+1.5036** | Urgency, credential harvesting, account verification markers |
| 17 | `email` | **+1.4875** | Urgency, credential harvesting, account verification markers |
| 18 | `password` | **+1.3945** | Urgency, credential harvesting, account verification markers |
| 19 | `notification` | **+1.3662** | Urgency, credential harvesting, account verification markers |
| 20 | `dear` | **+1.3545** | Urgency, credential harvesting, account verification markers |
| 21 | `dear customer` | **+1.3435** | Urgency, credential harvesting, account verification markers |
| 22 | `here to` | **+1.3049** | Urgency, credential harvesting, account verification markers |
| 23 | `2022` | **+1.3024** | Urgency, credential harvesting, account verification markers |
| 24 | `below` | **+1.3007** | Urgency, credential harvesting, account verification markers |
| 25 | `update your` | **+1.2885** | Urgency, credential harvesting, account verification markers |
| 26 | `mailbox` | **+1.2786** | Urgency, credential harvesting, account verification markers |
| 27 | `verify` | **+1.2749** | Urgency, credential harvesting, account verification markers |
| 28 | `click here` | **+1.2618** | Urgency, credential harvesting, account verification markers |
| 29 | `upgrade` | **+1.2364** | Urgency, credential harvesting, account verification markers |
| 30 | `document` | **+1.2267** | Urgency, credential harvesting, account verification markers |

---

