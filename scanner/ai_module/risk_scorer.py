import os
import joblib
from sklearn.ensemble import RandomForestClassifier


class RiskScorer:
    # Weights for the CVE-level risk score (CVSS severity vs. EPSS exploitability).
    CVSS_WEIGHT = 0.6
    EPSS_WEIGHT = 0.4
    # Environmental multipliers applied on top of the base score.
    PROD_BONUS = 0.15
    MONEY_BONUS = 0.15

    def __init__(self):
        #
        self.model_path = os.path.join(os.path.dirname(__file__), 'rf_contextual_model.pkl')
        self.model = self._init_model()

    def _init_model(self):
        if os.path.exists(self.model_path):
            return joblib.load(self.model_path)

        # : [TLSv1.0, Weak_Cipher, Is_Production, Financial_Data]
        X_train = [
            [1, 1, 1, 1],  #
            [1, 1, 1, 0],  #
            [1, 0, 0, 0],  #
            [0, 0, 1, 1],  #
            [0, 0, 0, 0]
        ]


        y_train = [10, 8, 4, 1, 0]


        model = RandomForestClassifier(n_estimators=150, random_state=42)
        model.fit(X_train, y_train)


        joblib.dump(model, self.model_path)
        return model

    def calculate_contextual_score(self, protocols, has_weak_cipher, is_prod=True, has_money=False):

        has_tls10 = 1 if "TLSv1.0" in protocols else 0
        weak_cipher_flag = 1 if has_weak_cipher else 0
        is_production = 1 if is_prod else 0
        financial_data = 1 if has_money else 0

        #test chaima
        features = [[has_tls10, weak_cipher_flag, is_production, financial_data]]

        #test mahdi now
        predicted_score = self.model.predict(features)[0]
        return float(predicted_score)

    def calculate_cve_risk_score(self, cvss_score, epss_score, is_prod=True, has_money=False):
        """Combine CVSS severity and EPSS exploitability into a 0-10 risk score.

        This is what lets the AI account for the technologies detected by
        WhatWeb: each technology's CVEs carry a CVSS (how severe) and an EPSS
        probability (how likely to be exploited), which are blended here and
        weighted up for production / financial-data contexts.

        Example: Apache 2.4.49 -> CVE-2021-41773 (CVSS 7.5, EPSS ~0.94) on a
        production financial site scores much higher than a CVSS 9.8 flaw that
        nobody exploits (low EPSS).
        """
        severity = max(0.0, min(float(cvss_score or 0.0), 10.0)) / 10.0
        exploitability = max(0.0, min(float(epss_score or 0.0), 1.0))

        base = (self.CVSS_WEIGHT * severity) + (self.EPSS_WEIGHT * exploitability)

        context = 1.0
        if is_prod:
            context += self.PROD_BONUS
        if has_money:
            context += self.MONEY_BONUS

        return round(min(10.0, base * 10.0 * context), 2)