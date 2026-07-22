#!/usr/bin/env python3
"""
生成贪吃蛇自动演示 SVG 动画
蛇会自己移动、吃食物、直到撞墙结束
"""

import random

# ============ 配置 ============
GRID_SIZE = 20
CELL_SIZE = 20
CANVAS_SIZE = GRID_SIZE * CELL_SIZE
BG_COLOR = "#1f2e38"
SNAKE_HEAD = "#7bed8a"
SNAKE_BODY_START = "#4CAF50"
SNAKE_BODY_END = "#1B5E20"
FOOD_COLOR = "#ff3b3b"
GRID_COLOR = "#2d4452"
FRAMES = 80  # 总帧数
MOVE_INTERVAL = 0.18  # 每帧间隔（秒）
# ==============================


def generate_frames():
    """生成动画帧序列"""
    # 初始化蛇（水平放置，头朝右）
    snake = [[9, 10], [8, 10], [7, 10], [6, 10]]
    direction = 'right'
    next_direction = 'right'
    score = 0
    game_over = False
    frames = []

    # 生成初始食物
    food = [12, 10]
    snake_set = set(tuple(p) for p in snake)
    while tuple(food) in snake_set:
        food = [random.randint(0, GRID_SIZE - 1), random.randint(0, GRID_SIZE - 1)]

    for _ in range(FRAMES):
        if game_over:
            # 游戏结束，重复最后一帧
            frames.append({
                'snake': snake.copy(),
                'food': food.copy() if food else [-1, -1],
                'score': score,
                'game_over': True,
                'direction': direction
            })
            continue

        # 更新方向（随机改变方向，增加观赏性）
        if random.random() < 0.15 and not game_over:
            possible = ['up', 'down', 'left', 'right']
            opposite = {'up': 'down', 'down': 'up', 'left': 'right', 'right': 'left'}
            # 移除反向
            possible = [d for d in possible if d != opposite.get(direction)]
            next_direction = random.choice(possible)

        if next_direction:
            opposite = {'up': 'down', 'down': 'up', 'left': 'right', 'right': 'left'}
            if opposite.get(next_direction) != direction:
                direction = next_direction

        # 计算新头部
        head = snake[0]
        new_head = head.copy()
        if direction == 'right':
            new_head[0] += 1
        elif direction == 'left':
            new_head[0] -= 1
        elif direction == 'up':
            new_head[1] -= 1
        elif direction == 'down':
            new_head[1] += 1

        # 检查是否吃到食物
        is_eating = (new_head[0] == food[0] and new_head[1] == food[1])

        # 构建新蛇
        new_snake = [new_head]
        end_index = len(snake) - (0 if is_eating else 1)
        for i in range(end_index):
            new_snake.append(snake[i])

        # 碰撞检测
        wall_collision = (new_head[0] < 0 or new_head[0] >= GRID_SIZE or
                          new_head[1] < 0 or new_head[1] >= GRID_SIZE)

        self_collision = False
        head_str = f"{new_head[0]},{new_head[1]}"
        for i in range(1, len(new_snake)):
            if f"{new_snake[i][0]},{new_snake[i][1]}" == head_str:
                self_collision = True
                break

        if wall_collision or self_collision:
            game_over = True
            frames.append({
                'snake': new_snake,
                'food': food.copy() if food else [-1, -1],
                'score': score,
                'game_over': True,
                'direction': direction
            })
            continue

        snake = new_snake

        # 处理吃到食物
        if is_eating:
            score += 1
            snake_set = set(tuple(p) for p in snake)
            if len(snake_set) >= GRID_SIZE * GRID_SIZE:
                game_over = True
                frames.append({
                    'snake': snake,
                    'food': food,
                    'score': score,
                    'game_over': True,
                    'direction': direction
                })
                continue

            # 生成新食物
            attempts = 0
            new_food = None
            while attempts < 2000:
                fx = random.randint(0, GRID_SIZE - 1)
                fy = random.randint(0, GRID_SIZE - 1)
                if (fx, fy) not in snake_set:
                    new_food = [fx, fy]
                    break
                attempts += 1

            if new_food:
                food = new_food
            else:
                # 兜底：遍历所有格子
                for y in range(GRID_SIZE):
                    for x in range(GRID_SIZE):
                        if (x, y) not in snake_set:
                            food = [x, y]
                            break
                    if food:
                        break

        frames.append({
            'snake': snake.copy(),
            'food': food.copy() if food else [-1, -1],
            'score': score,
            'game_over': False,
            'direction': direction
        })

    return frames


def render_svg(frames, output_path="snake.svg"):
    """渲染 SVG 动画"""
    parts = []

    # ====== SVG 头部 ======
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

    # ====== 每一帧 ======
    total_duration = len(frames) * MOVE_INTERVAL

    for idx, frame in enumerate(frames):
        begin = idx * MOVE_INTERVAL
        end = (idx + 1) * MOVE_INTERVAL if idx < len(frames) - 1 else total_duration

        snake = frame['snake']
        food = frame['food']
        game_over = frame['game_over']
        direction = frame.get('direction', 'right')
        score = frame['score']

        # ---- 食物 ----
        if food and food[0] >= 0 and not game_over:
            fx, fy = food
            cx = fx * CELL_SIZE + CELL_SIZE / 2
            cy = fy * CELL_SIZE + CELL_SIZE / 2
            parts.append(f'''
    <!-- 帧 {idx}: 食物 -->
    <g visibility="hidden">
        <set attributeName="visibility" to="visible" begin="{begin}s" end="{end}s"/>
        <circle cx="{cx}" cy="{cy}" r="{CELL_SIZE*0.38}" fill="{FOOD_COLOR}" class="food"/>
        <circle cx="{cx-2}" cy="{cy-3}" r="{CELL_SIZE*0.15}" fill="#ff8a8a" opacity="0.6"/>
    </g>''')

        # ---- 蛇 ----
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
    <!-- 帧 {idx}: 蛇节 {i} -->
    <g visibility="hidden">
        <set attributeName="visibility" to="visible" begin="{begin}s" end="{end}s"/>
        <rect x="{x}" y="{y}" width="{size}" height="{size}" rx="3" fill="{color}"/>''')

            # ---- 蛇头眼睛 ----
            if is_head:
                if direction == 'right':
                    ex1, ey1, ex2, ey2 = x + 9, y + 3, x + 9, y + 11
                    px1, py1, px2, py2 = 1, 0, 1, 0
                elif direction == 'left':
                    ex1, ey1, ex2, ey2 = x + 3, y + 3, x + 3, y + 11
                    px1, py1, px2, py2 = -1, 0, -1, 0
                elif direction == 'up':
                    ex1, ey1, ex2, ey2 = x + 3, y + 3, x + 11, y + 3
                    px1, py1, px2, py2 = 0, -1, 0, -1
                else:
                    ex1, ey1, ex2, ey2 = x + 3, y + 9, x + 11, y + 9
                    px1, py1, px2, py2 = 0, 1, 0, 1

                parts.append(f'''
        <circle cx="{ex1}" cy="{ey1}" r="2.5" fill="#f0faf4"/>
        <circle cx="{ex2}" cy="{ey2}" r="2.5" fill="#f0faf4"/>
        <circle cx="{ex1+px1}" cy="{ey1+py1}" r="1.2" fill="#0a1a1a"/>
        <circle cx="{ex2+px2}" cy="{ey2+py2}" r="1.2" fill="#0a1a1a"/>''')

            parts.append('''
    </g>''')

    # ====== 底部分数栏 ======
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

    # ====== 游戏结束蒙层 ======
    if frames and frames[-1]['game_over']:
        parts.append(f'''
    <!-- 游戏结束 -->
    <g>
        <rect x="0" y="0" width="{CANVAS_SIZE}" height="{CANVAS_SIZE}"
              fill="rgba(8,18,24,0.75)" visibility="hidden">
            <animate attributeName="visibility" to="visible"
                     begin="{total_duration}s" dur="0.01s" fill="freeze"/>
        </rect>
        <text x="{CANVAS_SIZE/2}" y="{CANVAS_SIZE/2 - 10}"
              text-anchor="middle" fill="#f28b82" font-size="30" font-weight="bold"
              visibility="hidden">
            💀 游戏结束
            <animate attributeName="visibility" to="visible"
                     begin="{total_duration}s" dur="0.01s" fill="freeze"/>
        </text>
        <text x="{CANVAS_SIZE/2}" y="{CANVAS_SIZE/2 + 30}"
              text-anchor="middle" fill="#bdd9d0" font-size="13"
              visibility="hidden">
            🔄 刷新页面重新播放
            <animate attributeName="visibility" to="visible"
                     begin="{total_duration}s" dur="0.01s" fill="freeze"/>
        </text>
    </g>''')

    parts.append('\n</svg>')

    # 写入文件
    content = ''.join(parts)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"✅ 已生成: {output_path}")
    print(f"📊 帧数: {len(frames)}, 时长: {total_duration:.1f}s")
    print(f"📝 大小: {len(content)} 字节")
    return True


if __name__ == "__main__":
    random.seed()
    print("🐍 生成贪吃蛇自动演示动画...")
    frames = generate_frames()
    render_svg(frames, "snake.svg")
    print("🎉 完成！")
