#!/usr/bin/env python3
"""
生成贪吃蛇自动演示 SVG 动画
蛇会主动寻找并吃掉食物
"""

import random

# ============ 配置 ============
GRID_SIZE = 20
CELL_SIZE = 20
CANVAS_SIZE = GRID_SIZE * CELL_SIZE
BG_COLOR = "#1f2e38"
SNAKE_HEAD = "#7bed8a"
FOOD_COLOR = "#ff3b3b"
GRID_COLOR = "#2d4452"
FRAMES = 200  # 更多帧
MOVE_INTERVAL = 0.15
# ==============================


def find_path_to_food(snake_head, food, snake_body_set):
    """选择离食物最近的可行方向"""
    head_x, head_y = snake_head
    food_x, food_y = food

    directions = [
        ('right', 1, 0),
        ('left', -1, 0),
        ('up', 0, -1),
        ('down', 0, 1),
    ]

    # 随机打乱，增加观赏性
    random.shuffle(directions)

    best_dir = None
    best_dist = float('inf')

    for direction, dx, dy in directions:
        new_x = head_x + dx
        new_y = head_y + dy

        if new_x < 0 or new_x >= GRID_SIZE or new_y < 0 or new_y >= GRID_SIZE:
            continue
        if (new_x, new_y) in snake_body_set:
            continue

        dist = abs(new_x - food_x) + abs(new_y - food_y)
        if dist < best_dist:
            best_dist = dist
            best_dir = direction

    # 如果没有可行方向，返回 None（保持原方向）
    return best_dir


def generate_frames():
    """生成动画帧"""
    # 初始蛇
    snake = [[9, 10], [8, 10], [7, 10], [6, 10]]
    direction = 'right'
    score = 0
    game_over = False
    frames = []

    # 初始食物
    food = [12, 10]
    snake_set = set(tuple(p) for p in snake)
    while tuple(food) in snake_set:
        food = [random.randint(0, GRID_SIZE - 1), random.randint(0, GRID_SIZE - 1)]

    for _ in range(FRAMES):
        # 记录当前帧
        frames.append({
            'snake': [p[:] for p in snake],
            'food': food[:] if food else [-1, -1],
            'score': score,
            'game_over': game_over,
            'direction': direction
        })

        if game_over:
            continue

        # 寻路
        body_set = set(tuple(p) for p in snake[1:])
        new_dir = find_path_to_food(snake[0], food, body_set)
        if new_dir:
            direction = new_dir

        # 移动
        head = snake[0]
        new_head = head[:]
        if direction == 'right':
            new_head[0] += 1
        elif direction == 'left':
            new_head[0] -= 1
        elif direction == 'up':
            new_head[1] -= 1
        elif direction == 'down':
            new_head[1] += 1

        is_eating = (new_head[0] == food[0] and new_head[1] == food[1])

        # 构建新蛇
        new_snake = [new_head]
        end_idx = len(snake) - (0 if is_eating else 1)
        for i in range(end_idx):
            new_snake.append(snake[i])

        # 碰撞检测
        wall = (new_head[0] < 0 or new_head[0] >= GRID_SIZE or
                new_head[1] < 0 or new_head[1] >= GRID_SIZE)

        self_hit = False
        for i in range(1, len(new_snake)):
            if new_snake[i][0] == new_head[0] and new_snake[i][1] == new_head[1]:
                self_hit = True
                break

        if wall or self_hit:
            game_over = True
            snake = new_snake
            continue

        snake = new_snake

        # 吃到食物
        if is_eating:
            score += 1
            snake_set = set(tuple(p) for p in snake)
            if len(snake_set) >= GRID_SIZE * GRID_SIZE:
                game_over = True
                continue

            # 生成新食物
            new_food = None
            for _ in range(2000):
                fx = random.randint(0, GRID_SIZE - 1)
                fy = random.randint(0, GRID_SIZE - 1)
                if (fx, fy) not in snake_set:
                    new_food = [fx, fy]
                    break
            if new_food:
                food = new_food
            else:
                for y in range(GRID_SIZE):
                    for x in range(GRID_SIZE):
                        if (x, y) not in snake_set:
                            food = [x, y]
                            break
                    if food:
                        break

    # 如果最后一帧不是 game_over，添加一个结束标记
    if not game_over:
        frames.append({
            'snake': [p[:] for p in snake],
            'food': food[:] if food else [-1, -1],
            'score': score,
            'game_over': True,
            'direction': direction
        })

    return frames


def render_svg(frames, output_path="snake.svg"):
    """渲染 SVG（使用 opacity 控制显示）"""
    parts = []

    # SVG 头部
    parts.append(f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     width="{CANVAS_SIZE}" height="{CANVAS_SIZE + 60}"
     viewBox="0 0 {CANVAS_SIZE} {CANVAS_SIZE + 60}"
     style="background: {BG_COLOR}; font-family: 'Segoe UI', sans-serif;">

    <defs>
        <style>
            @keyframes pulse {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.4; }}
            }}
            .food {{ animation: pulse 0.6s ease-in-out infinite; }}
        </style>
    </defs>

    <!-- 网格 -->
    <g stroke="{GRID_COLOR}" stroke-width="0.5" opacity="0.25">
''')

    for i in range(GRID_SIZE + 1):
        parts.append(f'        <line x1="{i*CELL_SIZE}" y1="0" x2="{i*CELL_SIZE}" y2="{CANVAS_SIZE}"/>')
        parts.append(f'        <line x1="0" y1="{i*CELL_SIZE}" x2="{CANVAS_SIZE}" y2="{i*CELL_SIZE}"/>')

    parts.append('    </g>\n')

    # 每一帧：使用 opacity 控制，默认透明
    for idx, frame in enumerate(frames):
        begin = idx * MOVE_INTERVAL
        duration = MOVE_INTERVAL

        snake = frame['snake']
        food = frame['food']
        game_over = frame['game_over']
        direction = frame.get('direction', 'right')

        # 所有元素放入一个组，用 opacity 控制显示
        parts.append(f'''
    <g opacity="0">
        <animate attributeName="opacity" to="1" begin="{begin}s" dur="{duration}s" fill="freeze"/>
        <animate attributeName="opacity" to="0" begin="{begin + duration}s" dur="0.01s" fill="freeze"/>''')

        # 食物（只在非 game_over 帧显示）
        if food and food[0] >= 0 and not game_over:
            fx, fy = food
            cx = fx * CELL_SIZE + CELL_SIZE / 2
            cy = fy * CELL_SIZE + CELL_SIZE / 2
            parts.append(f'''
        <circle cx="{cx}" cy="{cy}" r="{CELL_SIZE*0.38}" fill="{FOOD_COLOR}" class="food"/>
        <circle cx="{cx-2}" cy="{cy-3}" r="{CELL_SIZE*0.15}" fill="#ff8a8a" opacity="0.6"/>''')

        # 蛇
        for i, (sx, sy) in enumerate(snake):
            is_head = (i == 0)
            x = sx * CELL_SIZE + 1
            y = sy * CELL_SIZE + 1
            size = CELL_SIZE - 2

            if is_head:
                color = SNAKE_HEAD
            else:
                ratio = i / len(snake) if len(snake) > 1 else 0
                g = int(200 - 120 * ratio)
                r = int(30 + 60 * ratio)
                color = f"rgb({r}, {g}, 50)"

            parts.append(f'''
        <rect x="{x}" y="{y}" width="{size}" height="{size}" rx="3" fill="{color}"/>''')

            # 蛇头眼睛
            if is_head:
                if direction == 'right':
                    ex1, ey1, ex2, ey2 = x + 9, y + 3, x + 9, y + 11
                elif direction == 'left':
                    ex1, ey1, ex2, ey2 = x + 3, y + 3, x + 3, y + 11
                elif direction == 'up':
                    ex1, ey1, ex2, ey2 = x + 3, y + 3, x + 11, y + 3
                else:
                    ex1, ey1, ex2, ey2 = x + 3, y + 9, x + 11, y + 9

                parts.append(f'''
        <circle cx="{ex1}" cy="{ey1}" r="2.5" fill="#f0faf4"/>
        <circle cx="{ex2}" cy="{ey2}" r="2.5" fill="#f0faf4"/>
        <circle cx="{ex1+1}" cy="{ey1}" r="1.2" fill="#0a1a1a"/>
        <circle cx="{ex2+1}" cy="{ey2}" r="1.2" fill="#0a1a1a"/>''')

        parts.append('''
    </g>''')

    # 固定分数栏（一直显示）
    final_score = frames[-1]['score'] if frames else 0
    parts.append(f'''
    <!-- 分数栏 -->
    <g>
        <rect x="0" y="{CANVAS_SIZE}" width="{CANVAS_SIZE}" height="60" fill="{BG_COLOR}" opacity="0.95"/>
        <text x="{CANVAS_SIZE/2}" y="{CANVAS_SIZE + 35}"
              text-anchor="middle" fill="#b7e4d4" font-size="20" font-weight="bold">
            🍎 得分: <tspan fill="#f5c542">{final_score}</tspan>
        </text>
    </g>''')

    # 游戏结束蒙层（最后一帧之后显示）
    total_time = len(frames) * MOVE_INTERVAL
    parts.append(f'''
    <!-- 游戏结束蒙层 -->
    <g opacity="0">
        <animate attributeName="opacity" to="1" begin="{total_time}s" dur="0.5s" fill="freeze"/>
        <rect x="0" y="0" width="{CANVAS_SIZE}" height="{CANVAS_SIZE}" fill="rgba(8,18,24,0.75)"/>
        <text x="{CANVAS_SIZE/2}" y="{CANVAS_SIZE/2 - 10}"
              text-anchor="middle" fill="#f28b82" font-size="30" font-weight="bold">
            💀 游戏结束
        </text>
        <text x="{CANVAS_SIZE/2}" y="{CANVAS_SIZE/2 + 30}"
              text-anchor="middle" fill="#bdd9d0" font-size="13">
            🔄 刷新页面重新播放
        </text>
    </g>''')

    parts.append('\n</svg>')

    content = ''.join(parts)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"✅ 已生成: {output_path}")
    print(f"📊 总帧数: {len(frames)}, 时长: {len(frames) * MOVE_INTERVAL:.1f}s")
    print(f"🏆 最终得分: {final_score}")
    return True


if __name__ == "__main__":
    random.seed()
    print("🐍 生成贪吃蛇自动寻路演示动画...")
    frames = generate_frames()
    render_svg(frames, "snake.svg")
    print("🎉 完成！")
