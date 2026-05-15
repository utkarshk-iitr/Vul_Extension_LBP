from __future__ import absolute_import, division, print_function
import argparse
import logging
import os

import random

import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset, SequentialSampler, RandomSampler,TensorDataset
from torch.utils.data.distributed import DistributedSampler
from transformers import WEIGHTS_NAME, get_linear_schedule_with_warmup, RobertaConfig, RobertaModel, RobertaForSequenceClassification, RobertaTokenizer
from tqdm import tqdm

import pandas as pd
# metrics
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, PrecisionRecallDisplay
from sklearn.metrics import auc
import matplotlib.pyplot as plt

from tokenizers import Tokenizer
from model import MultiViewModel

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # Set the level (optional if already set)

fh = logging.FileHandler("on_bigvul_dataset.txt")
fh.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

class InputFeatures(object):
    def __init__(self,
                 raw_tokens,
                 raw_ids,
                 ast_tokens,
                 ast_ids,
                 pdg_tokens, 
                 pdg_ids, 
                 cfg_tokens, 
                 cfg_ids,
                 label):
        self.raw_tokens = raw_tokens
        self.raw_ids = raw_ids
        self.ast_tokens = ast_tokens
        self.ast_ids = ast_ids
        self.pdg_tokens = pdg_tokens
        self.pdg_ids = pdg_ids
        self.cfg_tokens = cfg_tokens
        self.cfg_ids = cfg_ids
        self.label = label
        

class TextDataset(Dataset):
    def __init__(self, raw_tokenizer, ast_tokenizer, pdg_tokenizer, cfg_tokenizer, args, file_type="train"):
        file_path = {
            "train": args.train_data_file,
            "eval": args.eval_data_file,
            "test": args.test_data_file
        }[file_type]

        self.examples = []
        df = pd.read_csv(file_path)
        raw_funcs = df["processed_func"].tolist()
        ast_funcs = df["ast_funcs"].tolist()
        pdg_funcs = df["pdg_funcs"].tolist()
        cfg_funcs = df["cfg_funcs"].tolist()
        labels = df["target"].tolist()


        for i in tqdm(range(len(raw_funcs))):
            self.examples.append(
                convert_examples_to_features(
                    raw_funcs[i], ast_funcs[i], pdg_funcs[i], cfg_funcs[i], labels[i],
                    raw_tokenizer, ast_tokenizer, pdg_tokenizer, cfg_tokenizer, args
                )
            )

        if file_type == "train":
            for example in self.examples[:3]:
                logger.info("*** Example ***")
                logger.info("label: {}".format(example.label))
                logger.info("raw_tokens: {}".format([x.replace('\u0120', '_') for x in example.raw_tokens]))
                logger.info("raw_ids: {}".format(' '.join(map(str, example.raw_ids))))
                logger.info("ast_tokens: {}".format([x.replace('\u0120', '_') for x in example.ast_tokens]))
                logger.info("ast_ids: {}".format(' '.join(map(str, example.ast_ids))))

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, i):       
        example = self.examples[i]
        raw_ids = torch.tensor(example.raw_ids)
        ast_ids = torch.tensor(example.ast_ids)
        pdg_ids = torch.tensor(example.pdg_ids)
        cfg_ids = torch.tensor(example.cfg_ids)
        label = torch.tensor(example.label)
        attention_mask_code = raw_ids.ne(1).long()  # pad_token_id = 1
        attention_mask_ast = ast_ids.ne(1).long()
        attention_mask_pdg = pdg_ids.ne(1).long()
        attention_mask_cfg = cfg_ids.ne(1).long()

        return (raw_ids, attention_mask_code,
                ast_ids, attention_mask_ast,
                pdg_ids, attention_mask_pdg,
                cfg_ids, attention_mask_cfg,
                label)



def convert_examples_to_features(raw_func, ast_func, pdg_func, cfg_func, label, raw_tokenizer, ast_tokenizer, pdg_tokenizer, cfg_tokenizer, args):

    def tokenize_and_pad(text, tokenizer):
        tokens = tokenizer.tokenize(str(text))[:args.block_size - 2]
        tokens = [tokenizer.cls_token] + tokens + [tokenizer.sep_token]
        ids = tokenizer.convert_tokens_to_ids(tokens)
        ids += [tokenizer.pad_token_id] * (args.block_size - len(ids))
        return tokens, ids

    raw_tokens, raw_ids = tokenize_and_pad(raw_func, raw_tokenizer)
    ast_tokens, ast_ids = tokenize_and_pad(ast_func, ast_tokenizer)
    pdg_tokens, pdg_ids = tokenize_and_pad(pdg_func, pdg_tokenizer)
    cfg_tokens, cfg_ids = tokenize_and_pad(cfg_func, cfg_tokenizer)

    return InputFeatures(raw_tokens, raw_ids, ast_tokens, ast_ids,
                         pdg_tokens, pdg_ids, cfg_tokens, cfg_ids, label)
    
def set_seed(args):
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    if args.n_gpu > 0:
        torch.cuda.manual_seed_all(args.seed)


def train(args, train_dataset, model, raw_tokenizer, ast_tokenizer, eval_dataset):
    from torch.utils.data import DataLoader, RandomSampler
    from transformers import get_linear_schedule_with_warmup
    from tqdm import tqdm
    import torch
    import os

    train_sampler = RandomSampler(train_dataset)
    train_dataloader = DataLoader(train_dataset, sampler=train_sampler,
                                  batch_size=args.train_batch_size, num_workers=0)

    args.max_steps = args.epochs * len(train_dataloader)
    args.save_steps = len(train_dataloader)
    args.warmup_steps = args.max_steps // 5
    args.eval_dataset = eval_dataset 

    model.to(args.device)

    no_decay = ['bias', 'LayerNorm.weight']
    optimizer_grouped_parameters = [
        {
            'params': [p for n, p in model.named_parameters() if not any(nd in n for nd in no_decay)],
            'weight_decay': args.weight_decay
        },
        {
            'params': [p for n, p in model.named_parameters() if any(nd in n for nd in no_decay)],
            'weight_decay': 0.0
        }
    ]

    optimizer = torch.optim.AdamW(optimizer_grouped_parameters, lr=args.learning_rate, eps=args.adam_epsilon)
    scheduler = get_linear_schedule_with_warmup(optimizer,
                                                num_warmup_steps=args.warmup_steps,
                                                num_training_steps=args.max_steps)

    if args.n_gpu > 1:
        model = torch.nn.DataParallel(model)

    global_step = 0
    best_f1 = 0.0
    model.zero_grad()

    for epoch in range(args.epochs):
        model.train()
        bar = tqdm(train_dataloader, total=len(train_dataloader))
        for step, batch in enumerate(bar):
            input_ids_raw, mask_raw, input_ids_ast, mask_ast, input_ids_pdg, mask_pdg,input_ids_cfg, mask_cfg, labels = [
                x.to(args.device) for x in batch
            ]

            loss, logits = model(
                input_ids_raw=input_ids_raw,
                attention_mask_raw=mask_raw,
                input_ids_ast=input_ids_ast,
                attention_mask_ast=mask_ast,
                input_ids_pdg=input_ids_pdg,
                attention_mask_pdg=mask_pdg,
                input_ids_cfg=input_ids_cfg,
                attention_mask_cfg=mask_cfg,
                labels=labels
            )


            if args.n_gpu > 1:
                loss = loss.mean()
            if args.gradient_accumulation_steps > 1:
                loss = loss / args.gradient_accumulation_steps

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), args.max_grad_norm)

            if (step + 1) % args.gradient_accumulation_steps == 0:
                optimizer.step()
                scheduler.step()
                model.zero_grad()
                global_step += 1

        results = evaluate(args, model, args.eval_dataset, eval_when_training=True)

        if results['eval_f1']>best_f1:
            best_f1=results['eval_f1']
            logger.info("  "+"*"*20)  
            logger.info("  Best f1:%s",round(best_f1,4))
            logger.info("  "+"*"*20)                          
            
            checkpoint_prefix = 'checkpoint-best-f1'
            output_dir = os.path.join(args.output_dir, '{}'.format(checkpoint_prefix))                        
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)                        
            model_to_save = model.module if hasattr(model,'module') else model
            output_dir = os.path.join(output_dir, '{}'.format(args.model_name)) 
            torch.save(model_to_save.state_dict(), output_dir)
            logger.info("Saving model checkpoint to %s", output_dir)


def evaluate(args, model, eval_dataset, eval_when_training=False):
    eval_dataloader = DataLoader(eval_dataset, sampler=SequentialSampler(eval_dataset),
                                 batch_size=args.eval_batch_size, num_workers=0)

    if args.n_gpu > 1 and not eval_when_training:
        model = torch.nn.DataParallel(model)

    model.eval()
    logits_list, labels_list = [], []

    for batch in eval_dataloader:
        input_ids_raw, mask_raw, input_ids_ast, mask_ast, input_ids_pdg, mask_pdg,input_ids_cfg, mask_cfg, labels = [x.to(args.device) for x in batch]
        with torch.no_grad():
 
            loss, logits = model(
                input_ids_raw=input_ids_raw,
                attention_mask_raw=mask_raw,
                input_ids_ast=input_ids_ast,
                attention_mask_ast=mask_ast,
                input_ids_pdg=input_ids_pdg,
                attention_mask_pdg=mask_pdg,
                input_ids_cfg=input_ids_cfg,
                attention_mask_cfg=mask_cfg,
                labels=labels
            )
        logits_list.append(logits.cpu().numpy())
        labels_list.append(labels.cpu().numpy())

    logits = np.concatenate(logits_list, axis=0)
    labels = np.concatenate(labels_list, axis=0)

    preds = logits[:, 1] > 0.5
    precision = precision_score(labels, preds)
    recall = recall_score(labels, preds)
    f1 = f1_score(labels, preds)

    result = {
        "eval_precision": precision,
        "eval_recall": recall,
        "eval_f1": f1,
        "eval_threshold": 0.5
    }

    PrecisionRecallDisplay.from_predictions(labels, logits[:, 1])
    plt.savefig(f'eval_precision_recall_{args.model_name}.pdf')

    for key in sorted(result.keys()):
        logger.info(f"{key} = {round(result[key], 4)}")

    return result



def test(args, model, test_dataset, best_threshold=0.5):
    test_dataloader = DataLoader(test_dataset, sampler=SequentialSampler(test_dataset),
                                 batch_size=args.eval_batch_size, num_workers=0)

    if args.n_gpu > 1:
        model = torch.nn.DataParallel(model)

    model.eval()
    logits_list, labels_list = [], []

    for batch in test_dataloader:
        input_ids_raw, mask_raw, input_ids_ast, mask_ast, input_ids_pdg, mask_pdg,input_ids_cfg, mask_cfg, labels = [x.to(args.device) for x in batch]
        with torch.no_grad():

            loss, logits = model(
                input_ids_raw=input_ids_raw,
                attention_mask_raw=mask_raw,
                input_ids_ast=input_ids_ast,
                attention_mask_ast=mask_ast,
                input_ids_pdg=input_ids_pdg,
                attention_mask_pdg=mask_pdg,
                input_ids_cfg=input_ids_cfg,
                attention_mask_cfg=mask_cfg,
                labels=labels
            )
        logits_list.append(logits.cpu().numpy())
        labels_list.append(labels.cpu().numpy())

    logits = np.concatenate(logits_list, axis=0)
    labels = np.concatenate(labels_list, axis=0)

    preds = logits[:, 1] > best_threshold
    precision = precision_score(labels, preds)
    recall = recall_score(labels, preds)
    acc = accuracy_score(labels, preds)
    f1 = f1_score(labels, preds)

    result = {
        "test_accuracy": acc,
        "test_precision": precision,
        "test_recall": recall,
        "test_f1": f1,
        "test_threshold": best_threshold
    }

    PrecisionRecallDisplay.from_predictions(labels, logits[:, 1])
    plt.savefig(f'test_precision_recall_{args.model_name}.pdf')

    import pandas as pd, os
    results_df = pd.DataFrame({
        "true_label": labels,
        "predicted_prob": logits[:, 1],
        "predicted_label": preds.astype(int)
    })
    results_df["model_name"] = args.model_name
    results_df["threshold"] = best_threshold

    output_dir = os.path.join(args.output_dir, "results")
    os.makedirs(output_dir, exist_ok=True)
    csv_path = os.path.join(output_dir, f"test_predictions_{args.model_name}.csv")
    results_df.to_csv(csv_path, index=False)

    logger.info(f"Saved per-sample predictions to {csv_path}")

    for key in sorted(result.keys()):
        logger.info(f"{key} = {round(result[key], 4)}")



    return result



def main():
    parser = argparse.ArgumentParser()
    ## parameters
    parser.add_argument("--train_data_file", default=None, type=str, required=False,
                        help="The input training data file (a csv file).")
    parser.add_argument('--view_fusion', type=str, default='mean', choices=['mean', 'concat'], help='How to fuse raw and AST views')

    parser.add_argument("--output_dir", default=None, type=str, required=False,
                        help="The output directory where the model predictions and checkpoints will be written.")
    parser.add_argument("--model_type", default="bert", type=str,
                        help="The model architecture to be fine-tuned.")
    parser.add_argument("--block_size", default=-1, type=int,
                        help="Optional input sequence length after tokenization."
                             "The training dataset will be truncated in block of this size for training."
                             "Default to the model max input length for single sentence inputs (take into account special tokens).")
    parser.add_argument("--eval_data_file", default=None, type=str,
                        help="An optional input evaluation data file to evaluate the perplexity on (a text file).")
    parser.add_argument("--test_data_file", default=None, type=str,
                        help="An optional input evaluation data file to evaluate the perplexity on (a text file).")
    parser.add_argument("--model_name", default="model.bin", type=str,
                        help="Saved model name.")
    parser.add_argument("--model_name_or_path", default=None, type=str,
                        help="The model checkpoint for weights initialization.")
    parser.add_argument("--config_name", default="", type=str,
                        help="Optional pretrained config name or path if not the same as model_name_or_path")
    parser.add_argument("--use_non_pretrained_model", action='store_true', default=False,
                        help="Whether to use non-pretrained model.")
    parser.add_argument("--tokenizer_name", default="", type=str,
                        help="Optional pretrained tokenizer name or path if not the same as model_name_or_path")
    parser.add_argument("--code_length", default=256, type=int,
                        help="Optional Code input sequence length after tokenization.") 

    parser.add_argument("--do_train", action='store_true',           
                        help="Whether to run training.")              
    parser.add_argument("--do_eval", action='store_true',           
                        help="Whether to run eval on the dev set.")
    parser.add_argument("--do_test", action='store_true',             
                        help="Whether to run eval on the dev set.")    

    parser.add_argument("--evaluate_during_training", action='store_true',
                        help="Run evaluation during training at each logging step.")
    parser.add_argument("--do_local_explanation", default=False, action='store_true',
                        help="Whether to do local explanation. ") 
    parser.add_argument("--reasoning_method", default=None, type=str,
                        help="Should be one of 'attention', 'shap', 'lime', 'lig'")

    parser.add_argument("--train_batch_size", default=4, type=int,
                        help="Batch size per GPU/CPU for training.")
    parser.add_argument("--eval_batch_size", default=4, type=int,
                        help="Batch size per GPU/CPU for evaluation.")
    parser.add_argument('--gradient_accumulation_steps', type=int, default=1,
                        help="Number of updates steps to accumulate before performing a backward/update pass.")
    parser.add_argument("--learning_rate", default=5e-5, type=float,
                        help="The initial learning rate for Adam.")
    parser.add_argument("--weight_decay", default=0.0, type=float,
                        help="Weight deay if we apply some.")
    parser.add_argument("--adam_epsilon", default=1e-8, type=float,
                        help="Epsilon for Adam optimizer.")
    parser.add_argument("--max_grad_norm", default=1.0, type=float,
                        help="Max gradient norm.")
    parser.add_argument("--max_steps", default=-1, type=int,
                        help="If > 0: set total number of training steps to perform. Override num_train_epochs.")
    parser.add_argument("--warmup_steps", default=0, type=int,
                        help="Linear warmup over warmup_steps.")
    parser.add_argument('--seed', type=int, default=42,
                        help="random seed for initialization")
    parser.add_argument('--epochs', type=int, default=1,
                        help="training epochs")
    # RQ2
    parser.add_argument("--effort_at_top_k", default=0.2, type=float,
                        help="Effort@TopK%Recall: effort at catching top k percent of vulnerable lines")
    parser.add_argument("--top_k_recall_by_lines", default=0.01, type=float,
                        help="Recall@TopK percent, sorted by line scores")
    parser.add_argument("--top_k_recall_by_pred_prob", default=0.2, type=float,
                        help="Recall@TopK percent, sorted by prediction probabilities")

    parser.add_argument("--do_sorting_by_line_scores", default=False, action='store_true',
                        help="Whether to do sorting by line scores.")
    parser.add_argument("--do_sorting_by_pred_prob", default=False, action='store_true',
                        help="Whether to do sorting by prediction probabilities.")
    
    args = parser.parse_args()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    args.n_gpu = torch.cuda.device_count()
    args.device = device
    args.fusion_strategy= "view_specific_heads"  # or 'hierarchical', 'bidirectional'
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(name)s -   %(message)s',datefmt='%m/%d/%Y %H:%M:%S',level=logging.INFO)
    logger.warning("device: %s, n_gpu: %s",device, args.n_gpu,)
    set_seed(args)
    config = RobertaConfig.from_pretrained(args.config_name if args.config_name else args.model_name_or_path)
    config.num_labels = 1   
    config.num_attention_heads = args.num_attention_heads

    ast_tokenizer = RobertaTokenizer.from_pretrained("microsoft/graphcodebert-base")
    pdg_tokenizer = RobertaTokenizer.from_pretrained("microsoft/graphcodebert-base")
    cfg_tokenizer = RobertaTokenizer.from_pretrained("microsoft/graphcodebert-base")
    
    raw_tokenizer = RobertaTokenizer.from_pretrained(args.tokenizer_name)
  
    config = RobertaConfig.from_pretrained(args.model_name_or_path)
    config.num_labels = 2

    encoder_raw = RobertaModel.from_pretrained(args.tokenizer_name, config=config)
    encoder_ast = RobertaModel.from_pretrained(args.model_name_or_path, config=config)
    encoder_cfg = RobertaModel.from_pretrained(args.model_name_or_path, config=config)
    encoder_pdg = RobertaModel.from_pretrained(args.model_name_or_path, config=config)
    model = MultiViewModel(encoder_raw, encoder_ast, encoder_pdg, encoder_cfg, config, args)


    logger.info("Training/evaluation parameters %s", args)
    if args.do_train:
        train_dataset = TextDataset(raw_tokenizer,ast_tokenizer, cfg_tokenizer,pdg_tokenizer, args, file_type='train')
        eval_dataset = TextDataset(raw_tokenizer,ast_tokenizer, cfg_tokenizer,pdg_tokenizer, args, file_type='eval')
        train(args, train_dataset, model, raw_tokenizer,ast_tokenizer, eval_dataset)
    results = {}

    if args.do_test:
        checkpoint_prefix = f'checkpoint-best-f1/{args.model_name}'
        output_dir = os.path.join(args.output_dir, '{}'.format(checkpoint_prefix))  
        model.load_state_dict(torch.load(output_dir, map_location=args.device), strict=False)
        model.to(args.device)
        test_dataset = TextDataset(raw_tokenizer,ast_tokenizer, cfg_tokenizer,pdg_tokenizer, args, file_type='test')
        test(args, model, test_dataset, best_threshold=0.5)
    return results
if __name__ == "__main__":
    main()
