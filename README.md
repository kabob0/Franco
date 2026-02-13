# Python Project

Un progetto Python strutturato con moduli, configurazione e logging.

## Struttura del Progetto

```
.
├── main.py              # Script principale
├── src/                 # Pacchetto sorgente
│   ├── __init__.py      # Inizializzazione pacchetto
│   ├── config.py        # Configurazione
│   ├── data_processor.py # Elaborazione dati
│   └── logger.py        # Setup logging
├── tests/               # Test unitari
├── data/                # Dati (creato automaticamente)
├── logs/                # Log (creato automaticamente)
├── requirements.txt     # Dipendenze
└── README.md            # Questo file
```

## Setup Iniziale

### 1. Creare Virtual Environment

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

### 2. Installare Dipendenze

```powershell
pip install -r requirements.txt
```

## Esecuzione

```powershell
python main.py
```

## Sviluppo

### Format Code
```powershell
black src/ main.py
```

### Linting
```powershell
pylint src/ main.py
```

### Test
```powershell
pytest tests/
```

## Moduli Principali

- **config.py**: Gestione della configurazione centralizzata
- **data_processor.py**: Elaborazione e trasformazione dati
- **logger.py**: Setup logging strutturato
- **main.py**: Entry point dell'applicazione
