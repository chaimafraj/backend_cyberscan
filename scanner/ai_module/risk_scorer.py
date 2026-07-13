import os
import joblib
from sklearn.ensemble import RandomForestClassifier


class RiskScorer:
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