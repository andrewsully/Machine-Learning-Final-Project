# Harvard-Data-Science-Final-Project

# Malicious URL Detection Software

## Project Overview
This project involves building a machine learning model to detect malicious URLs. The model will be trained on a dataset of URLs labeled as either malicious or benign, and will be used to classify new URLs as either safe or malicious.

The project includes the following steps:

1. Data wrangling and preprocessing: The raw dataset will be cleaned and preprocessed to prepare it for modeling.
2. Model training and tuning: A variety of machine learning models will be trained and their performance will be compared. The best performing model will be selected based on a combination of accuracy and efficiency.
3. Model deployment: The trained model will be integrated into a web application that allows users to input a URL and receive a prediction of whether it is safe or malicious.
4. Data Wrangling and Preprocessing
The raw dataset consists of a large number of URLs, each labeled as either malicious or benign. The first step in the project is to clean and preprocess the data to prepare it for modeling. This may include tasks such as handling missing values, removing duplicates, and encoding categorical variables.

## Model Training and Tuning
Once the data has been cleaned and preprocessed, it will be split into training and testing sets. A variety of machine learning models will be trained on the training set and their performance will be evaluated on the testing set. The models will be fine-tuned using techniques such as cross-validation and hyperparameter optimization. The best performing model will be selected based on its performance on the testing set.

## Model Deployment
The trained and tuned machine learning model will be integrated into a web application that allows users to input a URL and receive a prediction of whether it is safe or malicious. The application will be built using modern software engineering practices, including version control, testing, and continuous integration.

Repository Structure
The repository is organized as follows:

- `malicious_phish.csv`: contains the raw and preprocessed data used in the project

- `Detecting_malicious_URLs.ipynb`: contains the trained machine learning models and scripts for training and tuning them.
- `detection_interface.py`: contains the code for the web application that allows users to input a URL and receive a prediction from the model.
- `Written_Report.pdf`: documentation for the project, as well as a detailed analysis of our findings
