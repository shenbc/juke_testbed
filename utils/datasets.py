import os
import random
import numpy as np
from torch.utils.data import DataLoader
from torchvision import datasets, transforms

CURRENT_PATH = os.path.abspath(os.path.dirname(__file__))


class Partition(object):

    def __init__(self, data, index):
        self.data = data
        self.index = index

    def __len__(self):
        return len(self.index)

    def __getitem__(self, index):
        data_idx = self.index[index]
        return self.data[data_idx]


class DataLoaderHelper(object):
    def __init__(self, dataloader):
        self.loader = dataloader
        self.dataiter = iter(self.loader)

    def __next__(self):
        try:
            data, target = next(self.dataiter)
        except StopIteration:
            self.dataiter = iter(self.loader)
            data, target = next(self.dataiter)

        return data, target


class RandomPartitioner(object):

    def __init__(self, data, partition_sizes, seed=2021):
        self.data = data
        self.partitions = []
        rng = random.Random()
        rng.seed(seed)

        data_len = len(data)
        indexes = [x for x in range(0, data_len)]
        rng.shuffle(indexes)

        for frac in partition_sizes:
            part_len = round(frac * data_len)
            self.partitions.append(indexes[0:part_len])
            indexes = indexes[part_len:]

    def use(self, partition):
        selected_idxs = self.partitions[partition]

        return selected_idxs

    def __len__(self):
        return len(self.data)


class LabelwisePartitioner(object):                                                 # CIFAR10且data pattern = 0，即默认时：

    def __init__(self, data, partition_sizes, seed=2021):                           # partition_sizes = 10行9列，全0.111111...
        # sizes is a class_num * vm_num matrix
        self.data = data
        self.partitions = [list() for _ in range(len(partition_sizes[0]))]          # [[], [], [], [], [], [], [], [], []]，9个空list组成的list
        rng = random.Random()
        rng.seed(seed)

        label_indexes = list()
        class_len = list()
        # label_indexes includes class_num lists. Each list is the set of indexs of a specific class
        for class_idx in range(len(data.classes)):                                  # data.classes = ['apple', 'aquarium_fish', 'baby', ...
            # np.array(data.targets) == class_idx 返回一个含一系列true或false的list（如[true,false,false...]），当每个数据集的类别标签==class_idx时，该处为true
            # np.where 返回一个list，里面每个数为上面数组中true的下表（如np.where([True,True,True,False,True])返回array([0, 1, 2, 4]）
            # label_indexes存放的是从类别1到类别100对应的下标（如label_indexes[2][3]=6表示类别2的第三张图片在所有图片中下标为6）
            label_indexes.append(list(np.where(np.array(data.targets) == class_idx)[0])) 
            class_len.append(len(label_indexes[class_idx]))
            rng.shuffle(label_indexes[class_idx])

        # distribute class indexes to each vm according to sizes matrix
        # 两个循环，第一个循环遍历每类（这里为10类）
        # 第二个循环遍历0~8client
        # 当遍历第一类时（苹果的照片），遍历到第一台client时，将label_indexes[苹果]中前11.1%的照片分配给第一台client
        for class_idx in range(len(data.classes)):
            begin_idx = 0
            for vm_idx, frac in enumerate(partition_sizes[class_idx]):              # (vm_idx, frac) = (0, 0.111...),(2, 0.111...),(3, 0.111...)...其中0.111为该class分配给每个client照片的比例
                end_idx = begin_idx + round(frac * class_len[class_idx])
                end_idx = int(end_idx)
                self.partitions[vm_idx].extend(label_indexes[class_idx][begin_idx:end_idx])
                begin_idx = end_idx
        # 初始化后，self.partitions[5][6]=77表示第五台client的第六张图片在数据集中的下标为77

    def use(self, partition):
        selected_idxs = self.partitions[partition]

        return selected_idxs

    def __len__(self):
        return len(self.data)


def create_dataloaders(dataset, batch_size, selected_idxs=None, shuffle=True, pin_memory=True, num_workers=4):
    if selected_idxs == None:
        dataloader = DataLoader(dataset, batch_size=batch_size,
                                shuffle=shuffle, pin_memory=pin_memory, num_workers=num_workers)
    else:
        partition = Partition(dataset, selected_idxs)
        dataloader = DataLoader(partition, batch_size=batch_size,
                                shuffle=shuffle, pin_memory=pin_memory, num_workers=num_workers)

    return DataLoaderHelper(dataloader)


def load_datasets(dataset_type, data_path=CURRENT_PATH+'/../data/datasets'):
    train_transform = load_default_transform(dataset_type, train=True)
    test_transform = load_default_transform(dataset_type, train=False)
    train_dataset = None
    test_dataset = None

    if dataset_type == 'CIFAR10':
        train_dataset = datasets.CIFAR10(data_path, train=True,
                                         download=True, transform=train_transform)
        test_dataset = datasets.CIFAR10(data_path, train=False,
                                        download=True, transform=test_transform)

    elif dataset_type == 'CIFAR100':
        train_dataset = datasets.CIFAR100(data_path, train=True,
                                          download=True, transform=train_transform)
        test_dataset = datasets.CIFAR100(data_path, train=False,
                                         download=True, transform=test_transform)

    elif dataset_type == 'FashionMNIST':
        train_dataset = datasets.FashionMNIST(data_path, train=True,
                                              download=True, transform=train_transform)
        test_dataset = datasets.FashionMNIST(data_path, train=False,
                                             download=True, transform=test_transform)

    elif dataset_type == 'MNIST':
        train_dataset = datasets.MNIST(data_path, train=True,
                                       download=True, transform=train_transform)
        test_dataset = datasets.MNIST(data_path, train=False,
                                      download=True, transform=test_transform)
    return train_dataset, test_dataset


def load_default_transform(dataset_type, train=False):
    if dataset_type == 'CIFAR10':
        normalize = transforms.Normalize(mean=[0.4914, 0.4822, 0.4465],
                                         std=[0.2023, 0.1994, 0.2010])
        if train:
            dataset_transform = transforms.Compose([
                transforms.RandomHorizontalFlip(),
                transforms.RandomCrop(32, 4),
                transforms.ToTensor(),
                normalize
            ])
        else:
            dataset_transform = transforms.Compose([
                transforms.ToTensor(),
                normalize
            ])

    elif dataset_type == 'CIFAR100':
        dataset_transform = transforms.Compose([
            transforms.ToTensor(),
            transforms.Normalize((0.5, 0.5, 0.5), (0.5, 0.5, 0.5))
        ])

    elif dataset_type == 'FashionMNIST':
        dataset_transform = transforms.Compose([
            transforms.ToTensor(),
            transforms.Normalize((0.1307,), (0.3081,))
        ])

    elif dataset_type == 'MNIST':
        dataset_transform = transforms.Compose([
            transforms.ToTensor(),
            transforms.Normalize((0.1307,), (0.3081,))
        ])

    return dataset_transform

