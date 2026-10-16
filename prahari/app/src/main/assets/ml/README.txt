Drop the trained model here:

    model.tflite
    features.json

Produce them with ../../ml/train_naticusdroid.py (see ../../ml/README.md), then copy the two
files from ml/out/ into this folder. Until they exist, TfLiteMalwareModel returns null and the UI
simply hides the ML gauge — the app still runs. These two files are git-ignored by design.
