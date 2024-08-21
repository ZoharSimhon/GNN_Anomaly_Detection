from sklearn.metrics import accuracy_score, classification_report

def measure_results(graph):
    # Extracting the 'pred' and 'label' attributes
    y_pred = [data['pred'] for _, data in graph.nodes(data=True)]
    y_true = [data['label'] for _, data in graph.nodes(data=True)]

    # Calculate accuracy
    accuracy = accuracy_score(y_true, y_pred)
    print(f"Accuracy: {accuracy:.2f}")
    print(classification_report(y_true, y_pred))