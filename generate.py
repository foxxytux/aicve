from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

# specify the path where the model was saved
model_path = "fine-tuned_llama-3.2_3b_code"

# load the model and tokenizer
model = AutoModelForCausalLM.from_pretrained(model_path, device_map="cpu")
tokenizer = AutoTokenizer.from_pretrained(model_path)

# set model to evaluation mode
model.eval()

# example input
input_text = "write a python function to calculate fibonacci numbers."

# tokenize input
inputs = tokenizer(input_text, return_tensors="pt")

# run inference
with torch.no_grad():
    outputs = model.generate(inputs["input_ids"], max_length=200, num_beams=5)

# decode and print the output
response = tokenizer.decode(outputs[0], skip_special_tokens=True)
print(response)