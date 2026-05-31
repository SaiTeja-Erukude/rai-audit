from __future__ import annotations

import importlib

import numpy as np


def pytorch_grad_cam(model, inputs, target_layer, class_indices=None) -> np.ndarray:
    """Generate Grad-CAM heatmaps using PyTorch forward and backward hooks."""
    torch = _require_framework("torch", "torch")
    captured = {}

    def capture_activations(_module, _inputs, output):
        captured["activations"] = output

    def capture_gradients(_module, _grad_input, grad_output):
        captured["gradients"] = grad_output[0]

    forward_handle = target_layer.register_forward_hook(capture_activations)
    backward_handle = target_layer.register_full_backward_hook(capture_gradients)
    try:
        outputs = model(*inputs) if isinstance(inputs, (list, tuple)) else model(inputs)
        if outputs.ndim != 2:
            raise ValueError("PyTorch model output must have shape (batch, classes)")
        if class_indices is None:
            targets = outputs.argmax(dim=1)
        else:
            targets = torch.as_tensor(class_indices, device=outputs.device)
        model.zero_grad()
        outputs.gather(1, targets.reshape(-1, 1)).sum().backward()
        activations = captured["activations"]
        gradients = captured["gradients"]
        spatial_axes = tuple(range(2, gradients.ndim))
        weights = gradients.mean(dim=spatial_axes, keepdim=True)
        heatmaps = torch.relu((weights * activations).sum(dim=1))
        return _normalize_heatmaps(heatmaps.detach().cpu().numpy())
    finally:
        forward_handle.remove()
        backward_handle.remove()


def tensorflow_grad_cam(model, inputs, target_layer, class_indices=None) -> np.ndarray:
    """Generate Grad-CAM heatmaps using TensorFlow GradientTape."""
    tf = _require_framework("tensorflow", "tensorflow")
    layer = model.get_layer(target_layer) if isinstance(target_layer, str) else target_layer
    grad_model = tf.keras.models.Model(model.inputs, [layer.output, model.output])
    with tf.GradientTape() as tape:
        activations, outputs = grad_model(inputs)
        if len(outputs.shape) != 2:
            raise ValueError("TensorFlow model output must have shape (batch, classes)")
        if class_indices is None:
            targets = tf.argmax(outputs, axis=1, output_type=tf.int32)
        else:
            targets = tf.convert_to_tensor(class_indices, dtype=tf.int32)
        indices = tf.stack([tf.range(tf.shape(outputs)[0]), targets], axis=1)
        scores = tf.gather_nd(outputs, indices)
    gradients = tape.gradient(scores, activations)
    spatial_axes = tuple(range(1, len(gradients.shape) - 1))
    weights = tf.reduce_mean(gradients, axis=spatial_axes, keepdims=True)
    heatmaps = tf.nn.relu(tf.reduce_sum(weights * activations, axis=-1))
    return _normalize_heatmaps(heatmaps.numpy())


def _normalize_heatmaps(heatmaps: np.ndarray) -> np.ndarray:
    values = np.asarray(heatmaps, dtype=float)
    if values.ndim < 2:
        raise ValueError("heatmaps must have a batch dimension and at least one spatial dimension")
    flat = values.reshape(len(values), -1)
    maximums = flat.max(axis=1).reshape((len(values),) + (1,) * (values.ndim - 1))
    return np.divide(values, maximums, out=np.zeros_like(values), where=maximums > 0)


def _require_framework(module_name: str, extra_name: str):
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        raise ImportError(
            f"{module_name} is required for this Grad-CAM backend. "
            f"Install rai-audit-dl[{extra_name}]."
        ) from exc
