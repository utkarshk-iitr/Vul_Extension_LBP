
import torch
import torch.nn as nn
from torch.nn import CrossEntropyLoss
from transformers import RobertaModel

class RobertaClassificationHead(nn.Module):
    def __init__(self, config):
        super().__init__()
        self.dense = nn.Linear(config.hidden_size, config.hidden_size)
        self.dropout = nn.Dropout(config.hidden_dropout_prob)
        self.out_proj = nn.Linear(config.hidden_size, 2)

    def forward(self, features):
        x = self.dropout(features)
        x = self.dense(x)
        x = torch.tanh(x)
        x = self.dropout(x)
        logits = self.out_proj(x)
        return logits


class FocalLoss(nn.Module):
    def __init__(self, alpha=0.25, gamma=2):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, logits, targets):
        ce = nn.CrossEntropyLoss(reduction='none')(logits, targets)
        pt = torch.exp(-ce)
        focal = self.alpha * (1 - pt) ** self.gamma * ce
        return focal.mean()


class MultiViewModel(nn.Module):
    def __init__(self, encoder_raw, encoder_ast, encoder_pdg, encoder_cfg, config, args):
        super(MultiViewModel, self).__init__()

        self.encoder_raw = encoder_raw
        self.encoder_ast = encoder_ast
        self.encoder_pdg = encoder_pdg
        self.encoder_cfg = encoder_cfg
        self.args = args
        self.hidden_size = config.hidden_size

        self.dropout = nn.Dropout(config.hidden_dropout_prob)
        self.norms = nn.ModuleDict({
            'raw': nn.LayerNorm(self.hidden_size),
            'ast': nn.LayerNorm(self.hidden_size),
            'pdg': nn.LayerNorm(self.hidden_size),
            'cfg': nn.LayerNorm(self.hidden_size),
        })
        self.view_proj = nn.ModuleDict({
            'raw': nn.Linear(self.hidden_size, self.hidden_size),
            'ast': nn.Linear(self.hidden_size, self.hidden_size),
            'pdg': nn.Linear(self.hidden_size, self.hidden_size),
            'cfg': nn.Linear(self.hidden_size, self.hidden_size),
        })

        self.cross_modal_attention = nn.MultiheadAttention(self.hidden_size, num_heads=4, batch_first=True)

        gate_hidden=512
        gate_layers=4
        layers = []
        in_dim = self.hidden_size * 4
        for i in range(gate_layers - 1):
            layers.append(nn.Linear(in_dim, gate_hidden))
            layers.append(nn.ReLU())
            in_dim = gate_hidden
        layers.append(nn.Linear(in_dim, 4))
        layers.append(nn.Softmax(dim=-1))
        self.gate_mlp = nn.Sequential(*layers)


        self.bottleneck = nn.Sequential(
            nn.Linear(self.hidden_size * 4, self.hidden_size),
            nn.ReLU(),
            nn.Dropout(config.hidden_dropout_prob)
        )

        self.classifier = RobertaClassificationHead(config)

    def forward(self,
                input_ids_raw=None, attention_mask_raw=None,
                input_ids_ast=None, attention_mask_ast=None,
                input_ids_pdg=None, attention_mask_pdg=None,
                input_ids_cfg=None, attention_mask_cfg=None,
                labels=None):

        raw_cls = self.encoder_raw(input_ids=input_ids_raw, attention_mask=attention_mask_raw).last_hidden_state[:, 0, :]
        ast_cls = self.encoder_ast(input_ids=input_ids_ast, attention_mask=attention_mask_ast).last_hidden_state[:, 0, :]
        pdg_cls = self.encoder_pdg(input_ids=input_ids_pdg, attention_mask=attention_mask_pdg).last_hidden_state[:, 0, :]
        cfg_cls = self.encoder_cfg(input_ids=input_ids_cfg, attention_mask=attention_mask_cfg).last_hidden_state[:, 0, :]

        v_raw = self.norms['raw'](self.view_proj['raw'](raw_cls))
        v_ast = self.norms['ast'](self.view_proj['ast'](ast_cls))
        v_pdg = self.norms['pdg'](self.view_proj['pdg'](pdg_cls))
        v_cfg = self.norms['cfg'](self.view_proj['cfg'](cfg_cls))

        stacked_views = torch.stack([v_raw, v_ast, v_pdg, v_cfg], dim=1)

        # Cross-modal attention
        attn_output, _ = self.cross_modal_attention(stacked_views, stacked_views, stacked_views)
        attn_mean = attn_output.mean(dim=1)

        # Gating
        concat_views = torch.cat([v_raw, v_ast, v_pdg, v_cfg], dim=-1)
        gate_weights = self.gate_mlp(concat_views).unsqueeze(-1)
        gated_output = (stacked_views * gate_weights).sum(dim=1)

        # Residual-enhanced bottleneck
        bottleneck = self.bottleneck(concat_views)

        # Final fusion
        fused = 0.6 * gated_output + 0.3 * attn_mean + 0.1 * stacked_views.mean(dim=1)
        fused = fused + 0.25 * bottleneck

        fused = self.dropout(fused)
        logits = self.classifier(fused)
        probs = torch.softmax(logits, dim=-1)

        if labels is not None:
            loss_fct = FocalLoss(alpha=0.25, gamma=2.0)
            loss = loss_fct(logits, labels)
            return loss, probs
        else:
            return probs


