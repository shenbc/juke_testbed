import re
import os
import torch
import torch.nn.functional as F
import torch.nn as nn
import torchvision.models as m

CURRENT_PATH = os.path.abspath(os.path.dirname(__file__))


class m_AlexNet(nn.Module):
    def __init__(self):
        super(m_AlexNet, self).__init__()
        self.features = nn.Sequential(
            nn.Conv2d(3, 64, kernel_size=3, stride=2, padding=1),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=2),
            nn.Conv2d(64, 192, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=2),
            nn.Conv2d(192, 384, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.Conv2d(384, 256, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.Conv2d(256, 256, kernel_size=3, padding=1),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(kernel_size=2),
        )
        self.classifier = nn.Sequential(
            nn.Linear(256 * 2 * 2, 1024),
            nn.ReLU(inplace=True),
            nn.Linear(1024, 512),
            nn.ReLU(inplace=True),
            nn.Linear(512, 10),
        )

    def forward(self, x):
        x = self.features(x)
        x = x.view(-1, 256 * 2 * 2)
        x = self.classifier(x)
        return F.log_softmax(x, dim=1)

class LSTMnet(nn.Module):
    def __init__(self, in_dim, hidden_dim, n_layer, n_class):
        super(LSTMnet, self).__init__()
        self.n_layer = n_layer
        self.hidden_dim = hidden_dim
        self.lstm = nn.LSTM(in_dim, hidden_dim, n_layer, batch_first=True)
        self.linear = nn.Linear(hidden_dim, n_class)

    def forward(self, x):  # x‘s shape (batch_size, 序列长度, 序列中每个数据的长度)
        x=x.view(-1,32,32*3)
        out, _ = self.lstm(x)  # out‘s shape (batch_size, 序列长度, hidden_dim)
        out = out[:, -1, :]  # 中间的序列长度取-1，表示取序列中的最后一个数据，这个数据长度为hidden_dim，
        # 得到的out的shape为(batch_size, hidden_dim)
        out = self.linear(out)  # 经过线性层后，out的shape为(batch_size, n_class)
        return out


def get_model(model_name, download=False):
    """
    :param model_name: alexnet vgg11 vgg16 vgg19 resnet50 resnet101 resnet152
    :return: model instance
    """
    model = None

    if model_name == 'squeezenet':
        model = m.squeezenet1_0(num_classes=10)
    elif model_name == 'vgg16':
        model = m.vgg16(num_classes=10)
    elif model_name == 'vgg19':
        model = m.vgg19(num_classes=10)
    elif model_name == 'alexnet':
        model = m_AlexNet()
    elif model_name == 'resnet18':
        model = m.resnet18(num_classes=10)
    elif model_name == 'resnet50':
        model = m.resnet50(num_classes=10)
    elif model_name == 'lstm':
        model = LSTMnet(32*3,1800,18,10)


    if model is not None:
        model.eval()
    return model
