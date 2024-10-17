from sklearn.metrics import accuracy_score, classification_report

def measure_results(graph):
    # Extracting the 'pred' and 'label' attributes
    pred = [data['pred'] for _, data in graph.nodes(data=True)]
    label = [data['label'] for _, data in graph.nodes(data=True)]

    # Calculate accuracy
    accuracy = accuracy_score(label, pred)
    print(f"Accuracy: {accuracy:.2f}")
    print(classification_report(label, pred))