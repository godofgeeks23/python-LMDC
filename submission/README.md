Linux malware detection and classification (LMDC)

Instructions - 

    1.  Place the elf files in the 'elfs' folder.
    2.  It is advisable to run 'cleaner.py' to remove the files that are not ELF files or are invalid/corrupted.
        To run the cleaner.py, run the following command:
            python cleaner.py
    3.  Run the following command to run the script:
            python LMDC_test.py elfs
    4.  The output is stored as result.csv in the current directory.

Notes - 

    1.  During cleaning, an error may be encountered. This is because the files are not proper ELF files.
        In this case, we have to manually remove that ELF file from the 'elfs' folder.
        This can be automated though using excpetion handling in python.
    2.  If any entry in result.csv is missing, that is because the file was removed during cleaning.
        
Our Approach - 

    We have used supervised learning techniques to tackle this problem.
    
    Data Preparation - 
        We uncompressed all the files which were provided to us after renaming them by their class-name.
        Now we cleaned the data by cleaner.py.
        Now the features are extracted from the files and saved in a CSV file.
        We added a last column  in this CSV named type which contains the class-name of the file. This became our target variable.
        Then we cleaned the dataset by filling in missing values and other things.

    Model Training - 
        We have used Random Forest Classifier to train our model.
        We generated training and test data using train_test_split function.
        After the model is trained, we saved the model as finalized_model.sav.

    Model Testing -
        We also tested the model on the test data.
        Accuracy and F1 score of the model is calculated and can be viewed by un-commenting the training function.
        The accuracy and F1 score are printed in the console.
    
    Generating the result - 
        The trained model is loaded, and we use the data from perfect.csv to predict the class-name of the files.
        File names with their respective predicted class-name is saved in result.csv.