import os
import torch  # 🆕
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM


class VulnRecommender:
    def __init__(self):
        #
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.model_path = os.path.join(base_dir, 'ai_module', 'flan_model')

        #
        if not os.path.exists(self.model_path):
            self.model_path = "google/flan-t5-base"

        #
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        self.model = AutoModelForSeq2SeqLM.from_pretrained(self.model_path)

    def generate_remediation(self, cve_id, description):
        #
        prompt = (
            f"En tant qu'expert en cybersécurité, fournis une solution technique concise "
            f"et des actions correctives en français pour la vulnérabilité {cve_id}. "
            f"Description: {description}\n\nSolution:"
        )

        #
        inputs = self.tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)

        #
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=250,
                num_beams=4,
                early_stopping=True,
                no_repeat_ngram_size=2
            )

        #
        input_length = inputs.input_ids.shape[1]
        remediation = self.tokenizer.decode(outputs[0][input_length:], skip_special_tokens=True)

        return remediation.strip()