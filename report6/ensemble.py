# simple model agreement
def evaluate_threat_level(svm_result: int, rf_result: int):
    if svm_result == 1 and rf_result == 1:
        return "HIGH"
    elif svm_result == 1 or rf_result == 1:
        return "MEDIUM"
    else:
        return "NORMAL"