# Network Intrusion Detection System (NIDS) using AI & ML

## Project Objective
Develop a system to detect network intrusions by analyzing network traffic and classifying connections as **Normal** or **Attack** using:

- Random Forest Machine Learning  
- Apriori Association Rule Mining  
- Real-time packet capture with Scapy  
- Flask backend APIs  
- Interactive web frontend  

The system outputs predictions with confidence scores for real-time monitoring and batch analysis.

---

## Dataset Details
- **Total records:** 25,192  
- **Features:** 42 (numeric and categorical)  
- **Label:** `is_attack` (0 = normal, 1 = attack)  
- **Class distribution:** Normal = 13,449, Attack = 11,743  
- **Categorical features:** `protocol_type`, `service`, `flag`  
- **Key numeric features:** `duration`, `src_bytes`, `dst_bytes`, `count`, `srv_count`, `same_srv_rate`  

Dataset supports training for Apriori rule mining and Random Forest model.

---

## Algorithm / Model Used
- **Apriori Association Rule Mining:** Discovers frequent itemsets and strong association rules linked to attacks (~288 rules generated).  
- **Random Forest Classifier:** Supervised ensemble model trained with 100 trees, 70%-30% split, achieving ~98% accuracy.  
- **Real-Time Capture:** Scapy live packet sniffing for continuous intrusion analysis.  
- **Flask Backend:** Serves ML models and rules with RESTful endpoints.  
- **Web Frontend:** User interface providing manual entry, CSV upload, live capture controls, and realtime stats.

---

## Results
- **Accuracy:** 98%  
- **Precision (Attack):** 0.99  
- **Recall (Attack):** 0.96  
- **Confusion Matrix Highlights:**  
  - True Normal: 3997  
  - False Positive: 38  
  - True Attack: 3380  
  - False Negative: 143  
- Apriori rules enhance interpretability by exposing common attack patterns.

![Model Accuracy](images/Screenshot 2025-11-16 171005.png)

![Model Accuracy](https://github.com/vanshikas20/Network-intrusion-detection-system/blob/main/images/Screenshot%202025-11-16%20171005.png)


---

## Conclusion
The hybrid Apriori + Random Forest system accurately detects network intrusions with explainable insights. Real-time packet processing fused with a web interface enables effective network security monitoring.

---

## Future Scope
- Incorporate Apriori rules for real-time prediction explanations.  
- Extend to multi-class attack detection (DoS, Probe, R2L, U2R).  
- Implement UI alerts and notifications.  
- Enhance frontend with charts and analytics dashboards.  
- Scale using cloud and distributed processing techniques.

---

## References
- Breiman, L. (2001). *Random Forests*. Machine Learning.  
- Agrawal, R., & Srikant, R. (1994). *Fast Algorithms for Mining Association Rules in Large Databases*. VLDB.  
- [Scapy](https://scapy.net)  
- [Flask](https://flask.palletsprojects.com)  
- [mlxtend](https://rasbt.github.io/mlxtend/)  
- Snort and Suricata Open Source IDS Tools  

---
