# minimal shim used only to satisfy pickle during joblib.load
# The real training script had a function named `clean_text`.
def clean_text(x):
    try:
        return x.lower()
    except Exception:
        return x

# add any other helper names referenced by the pickle as plain stubs here
