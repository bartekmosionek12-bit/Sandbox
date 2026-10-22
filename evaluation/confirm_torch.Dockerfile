# Image for confirm_bypasses.py: PyTorch (CPU, conda-forge) for loading a candidate with
# torch.load inside deep mode's isolation (confirm_bypasses.py passes the same docker
# run flags as safeloadai.docker_sandbox). Nothing from the repo is copied in. Build:
#   docker build -t safeloadai-confirm-torch:latest - < evaluation/confirm_torch.Dockerfile
FROM mambaorg/micromamba:2.0.5
RUN micromamba install -y -n base -c conda-forge python=3.11 "pytorch-cpu=2.9" numpy joblib scikit-learn \
    && micromamba clean -a -y
ENV PATH=/opt/conda/bin:$PATH
