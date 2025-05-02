"""
Web application for steganography and hidden malware detection
"""

import streamlit as st
import numpy as np
import matplotlib.pyplot as plt
import os
import tempfile
from PIL import Image
import io
import time

from stego_detector import StegoDetector

st.set_page_config(page_title="Steganography & Malware Detector", layout="wide")
st.title("AI-Based Steganography & Hidden Malware Detector")
st.markdown("""
This application uses AI to detect hidden messages (steganography) and potential 
malware in files. It can analyze images, audio files, and other binary files for 
signs of hidden content.
""")


@st.cache_resource
def get_detector():
    detector = StegoDetector()
    return detector


detector = get_detector()

st.sidebar.title("Options")
analysis_type = st.sidebar.selectbox(
    "Analysis Type",
    ["Steganography Detection", "Malware Detection", "Data Extraction"]
)

uploaded_file = st.file_uploader("Upload a file for analysis", type=[
    "png", "jpg", "jpeg", "bmp", "wav", "mp3", "pdf", "exe", "bin", "txt"])


def save_uploaded_file(uploaded_file):
    if uploaded_file is not None:
        with tempfile.NamedTemporaryFile(delete=False, suffix="." + uploaded_file.name.split(".")[-1]) as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            return tmp_file.name
    return None


def get_file_type(file_path):
    if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
        return "image"
    elif file_path.lower().endswith(('.wav', '.mp3')):
        return "audio"
    else:
        return "binary"


results_area = st.container()
viz_area = st.container()
progress_area = st.container()

if uploaded_file is not None:
    file_path = save_uploaded_file(uploaded_file)
    file_type = get_file_type(file_path)

    st.subheader("File Preview")
    col1, col2 = st.columns([1, 2])

    with col1:
        st.text(f"File name: {uploaded_file.name}")
        st.text(f"File size: {uploaded_file.size / 1024:.2f} KB")
        st.text(f"File type: {file_type.capitalize()}")

    with col2:
        if file_type == "image":
            img = Image.open(uploaded_file)
            st.image(img, width=300)
        elif file_type == "audio":
            st.audio(uploaded_file)
        else:
            st.text("Preview not available for this file type")

    if st.button("Run Analysis"):
        with progress_area:
            progress_bar = st.progress(0)
            status_text = st.empty()

            if analysis_type == "Steganography Detection":
                status_text.text("Analyzing file for hidden content...")
                progress_bar.progress(25)
                time.sleep(0.5)

                if file_type == "image":
                    result = detector.detect_image_steganography(file_path)
                    progress_bar.progress(50)
                    status_text.text("Generating visualizations...")

                    with viz_area:
                        st.subheader("Visual Analysis")
                        fig, ax = plt.subplots(2, 2, figsize=(12, 8))
                        img = Image.open(file_path)
                        img_array = np.array(img)

                        ax[0, 0].imshow(img_array)
                        ax[0, 0].set_title("Original Image")
                        ax[0, 0].axis('off')

                        if len(img_array.shape) == 3:
                            lsb = img_array[:, :, 0] % 2 * 255
                        else:
                            lsb = img_array % 2 * 255

                        ax[0, 1].imshow(lsb, cmap='gray')
                        ax[0, 1].set_title("LSB Plane")
                        ax[0, 1].axis('off')

                        if len(img_array.shape) == 3:
                            ax[1, 0].hist(img_array[:, :, 0].flatten(), bins=256, color='r', alpha=0.5)
                            ax[1, 0].hist(img_array[:, :, 1].flatten(), bins=256, color='g', alpha=0.5)
                            ax[1, 0].hist(img_array[:, :, 2].flatten(), bins=256, color='b', alpha=0.5)
                        else:
                            ax[1, 0].hist(img_array.flatten(), bins=256, color='gray')
                        ax[1, 0].set_title("Color Histogram")

                        import cv2

                        gray = np.mean(img_array, axis=2).astype(np.uint8) if len(img_array.shape) == 3 else img_array
                        blur = cv2.GaussianBlur(gray, (5, 5), 0)
                        noise = np.abs(gray.astype(float) - blur.astype(float))
                        ax[1, 1].imshow(noise, cmap='hot')
                        ax[1, 1].set_title("Noise Estimation")
                        ax[1, 1].axis('off')

                        plt.tight_layout()
                        st.pyplot(fig)

                elif file_type == "audio":
                    result = detector.detect_audio_steganography(file_path)
                    progress_bar.progress(50)
                    with viz_area:
                        st.subheader("Audio Analysis")
                        try:
                            import wave
                            import struct
                            from scipy.fft import fft

                            with wave.open(file_path, 'rb') as wav_file:
                                n_channels = wav_file.getnchannels()
                                sample_width = wav_file.getsampwidth()
                                framerate = wav_file.getframerate()
                                n_frames = wav_file.getnframes()
                                signal = wav_file.readframes(n_frames)

                                if sample_width == 1:
                                    samples = np.array(struct.unpack(f"{n_frames}B", signal))
                                elif sample_width == 2:
                                    samples = np.array(struct.unpack(f"{n_frames}h", signal))

                                if n_channels == 2:
                                    samples = samples[::2]

                                samples = samples[:100000]

                                fig, ax = plt.subplots(2, 2, figsize=(12, 8))
                                ax[0, 0].plot(samples[:10000])
                                ax[0, 0].set_title("Waveform")

                                fft_vals = np.abs(fft(samples))
                                fft_vals = fft_vals[:len(fft_vals) // 2]
                                ax[0, 1].plot(fft_vals[:10000])
                                ax[0, 1].set_title("Frequency Spectrum")

                                lsb = samples % 2
                                ax[1, 0].plot(lsb[:10000])
                                ax[1, 0].set_title("LSB Values")

                                lsb_counts = np.bincount(lsb[:10000])
                                ax[1, 1].bar(['0', '1'], lsb_counts)
                                ax[1, 1].set_title("LSB Distribution")

                                plt.tight_layout()
                                st.pyplot(fig)
                        except Exception as e:
                            st.error(f"Error generating audio visualization: {e}")

                else:
                    result = detector.detect_binary_steganography(file_path)
                    progress_bar.progress(50)

                progress_bar.progress(100)
                status_text.text("Analysis complete!")

                with results_area:
                    st.subheader("Steganography Detection Results")
                    col1, col2 = st.columns(2)
                    if result and 'contains_hidden_data' in result:
                        with col1:
                            if result['contains_hidden_data']:
                                st.error("⚠️ Hidden content detected!")
                            else:
                                st.success("✓ No hidden content detected")
                        with col2:
                            st.metric("Confidence", f"{result['confidence'] * 100:.1f}%")
                        st.json(result)
                    else:
                        st.error("Analysis failed or returned no results")

            elif analysis_type == "Malware Detection":
                status_text.text("Scanning for malicious content...")
                progress_bar.progress(40)
                time.sleep(0.7)
                result = detector.detect_malware_steganography(file_path)
                progress_bar.progress(100)
                status_text.text("Analysis complete!")

                with results_area:
                    st.subheader("Malware Detection Results")
                    col1, col2 = st.columns(2)
                    if result and 'suspicious_indicators' in result:
                        with col1:
                            if result['malware_probability'] > 0.5:
                                st.error("⚠️ Suspicious content detected!")
                            elif result['malware_probability'] > 0.1:
                                st.warning("⚠️ Possibly suspicious content")
                            else:
                                st.success("✓ No malicious content detected")
                        with col2:
                            st.metric("Risk Score", f"{result['malware_probability'] * 100:.1f}%")
                        st.subheader("Suspicious Indicators")
                        for indicator in result['suspicious_indicators']:
                            st.warning(indicator)
                        st.json(result)
                    else:
                        st.error("Analysis failed or returned no results")

            elif analysis_type == "Data Extraction":
                status_text.text("Attempting to extract hidden data...")
                progress_bar.progress(30)
                time.sleep(0.8)

                output_dir = tempfile.mkdtemp()
                output_path = os.path.join(output_dir, "extracted_data")
                result = detector.extract_hidden_data(file_path, output_path)

                progress_bar.progress(100)
                status_text.text("Extraction complete!")

                with results_area:
                    st.subheader("Data Extraction Results")
                    if result and 'detected_type' in result:
                        st.success(f"Successfully extracted {result['size']} bytes of data")
                        st.text(f"Detected file type: {result['detected_type']}")
                        st.subheader("Sample of Extracted Data")
                        with open(output_path, 'rb') as f:
                            content = f.read(100)
                            st.code(content)
                    else:
                        st.error("No hidden data could be extracted")
