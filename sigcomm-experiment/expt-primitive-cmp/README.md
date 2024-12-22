# primitive comparison

This experiment will compare two side send with one side write with immediate data.

## CPU usage on Receiver side

On one machine start the server program with

```
python cmp.py -p 10001 -c cmd_gen -d mlx5_2 -i 1 -x 3

```

On the other machine start the other server program with


```
python cmp.py -p 10001 -c cmd_gen -d mlx5_2 -i 1 -x 3 -H 10.10.1.1

```

