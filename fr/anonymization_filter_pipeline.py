"""
title: Anonymization Filter Pipeline
author: Cypog
description: Un pipeline de filtrage pour anonymiser les données sensibles dans les requêtes avant traitement.
version: 0.1
license: MIT
"""

import re
import uuid
from typing import List, Optional
from pydantic import BaseModel


class Pipeline:
    class Valves(BaseModel):
        pipelines: List[str] = []
        priority: int = 0

    def __init__(self):
        """
        Initialiser le pipeline avec un type, un nom et des valves par défaut.
        """
        self.type = "filter"
        self.name = "Anonymization Filter"
        self.valves = self.Valves(
            **{
                "pipelines": ["*"],
                "priority": 0,
            }
        )

    async def inlet(self, body: dict, user: Optional[dict] = None) -> dict:
        """
          Traiter les données entrantes en anonymisant les informations sensibles avant de les envoyer au modèle.
        """
        print(f"inlet:{__name__}")
        print(f"Received body: {body}")
        print(f"User: {user}")

        # Générer un ID de chat si il est manquant
        if "chat_id" not in body:
            unique_id = f"SYSTEM MESSAGE {uuid.uuid4()}"
            body["chat_id"] = unique_id
            print(f"chat_id was missing, set to: {unique_id}")

        required_keys = ["model", "messages"]
        missing_keys = [key for key in required_keys if key not in body]
        if missing_keys:
            raise ValueError(f"Missing keys in the request body: {', '.join(missing_keys)}")

        # Anonymiser le dernier message utilisateur
        body["messages"][-1]["content"] = self.anonymize_text(body["messages"][-1]["content"])

        return body

    async def outlet(self, body: dict, user: Optional[dict] = None) -> dict:
        """
        Process outgoing data (optional).
        """
        print(f"outlet:{__name__}")
        print(f"Received body: {body}")
        return body

    def anonymize_text(self, text: str) -> str:
        """
        Anonymize sensitive data within a text.
        """
        patterns = {
            r"[A-Z][a-z]+\s[A-Z][a-z]+": "[nom_prénom]",  # Nom completq
            r"\b[M|Mme|Mlle|Dr|Pr]\b": "[civilité]",  # Civilités
            r"\b\d{2}/\d{2}/\d{4}\b": "[date_naissance]",  # Dates au format JJ/MM/AAAA
            r"\b(\+?\d{1,3}[-.\s]?)?(\d{2}[-.\s]?){4,5}\b": "[numéro_téléphone]",  # numéros de téléphone
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}": "[email]",  # Adresses email
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b": "[adresse_IP]",  # IP addresses
            r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b": "[numéro_sécurité_sociale]",  # NIR Français
        }
        # Pour chaque motif et remplacement dans le dictionnaire patterns
        for pattern, replacement in patterns.items():
            # Remplacer les occurrences du motif par le texte de remplacement
            text = re.sub(pattern, replacement, text)

        # Anonymiser des motifs spécifiques comme "Nom : ****" ou "Prénom : *****"
        text = self.anonymize_named_fields(text, ["Nom", "Prénom"])

        return text

    def anonymize_named_fields(self, text: str, fields: List[str]) -> str:
        """
        Anonymize content following specific fields like 'Nom :' or 'Prénom :'.
        """
        for field in fields:
             # Créer un motif pour le champ et anonymiser le contenu correspondant
            pattern = rf"{field}\s*:\s*[^\n]+"
            text = re.sub(pattern, f"{field} : [anonymisé]", text)
        return text

    async def on_startup(self):
        """
        Actions to perform when the pipeline starts (optional).
        """
        print(f"{self.name} started successfully.")

    async def on_shutdown(self):
        """
        Actions to perform when the pipeline stops (optional).
        """
        print(f"{self.name} stopped successfully.")
