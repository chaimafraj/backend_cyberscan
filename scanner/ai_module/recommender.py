import torch

from .flan import get_flan_model


class VulnRecommender:
    def __init__(self):
        self.tokenizer, self.model = get_flan_model()

    def generate_remediation(self, cve_id, description):
        prompt = (
            f"En tant qu'expert en cybersécurité, fournis une solution technique concise "
            f"et des actions correctives en français pour la vulnérabilité {cve_id}. "
            f"Description: {description}\n\nSolution:"
        )

        inputs = self.tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=250,
                num_beams=4,
                early_stopping=True,
                no_repeat_ngram_size=2
            )

        # Flan-T5 (seq2seq) : generate() renvoie uniquement les tokens générés
        # (pas le prompt d'entrée). Ne pas découper avec input_length.
        remediation = self.tokenizer.decode(outputs[0], skip_special_tokens=True)

        return remediation.strip()
