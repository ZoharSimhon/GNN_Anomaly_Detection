from sklearn.metrics import accuracy_score, classification_report

def measure_results(pred, label):
    # Extracting the 'pred' and 'label' attributes
    # y_pred = [data['pred'] for _, data in graph.nodes(data=True)]
    # y_true = [data['label'] for _, data in graph.nodes(data=True)]

    # Calculate accuracy
    accuracy = accuracy_score(label, pred)
    print(f"Accuracy: {accuracy:.2f}")
    print(classification_report(label, pred))