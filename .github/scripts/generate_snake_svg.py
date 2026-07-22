#!/usr/bin/env python3
"""
生成贪吃蛇 GIF 动图
需要安装: pip install pillow
"""

import random
from PIL import Image, ImageDraw, ImageFont
import os

GRID_SIZE = 20
CELL_SIZE = 20
CANVAS_SIZE = GRID_SIZE * CELL_SIZE
BG_COLOR = (31, 46, 56)
SNAKE_HEAD = (123, 237, 138)
SNAKE_BODY = (46, 139, 87)
FOOD_COLOR = (255, 59, 59)
GRID_COLOR = (45, 68, 82)
FRAMES = 80
MOVE_INTERVAL = 150  # 毫秒

def generate_snake_frames():
    """生成贪吃蛇动画的每一帧"""
    snake = [[9, 10], [8, 10], [7, 10], [6, 10]]
    direction = 'right'
    next_direction = 'right'
    food = [12, 10]
    snake_set = set(tuple(p) for p in snake)
    while tuple(food) in snake_set:
        food = [random.randint(0, GRID_SIZE-1), random.randint(0, GRID_SIZE-1)]
    
    frames = []
    score = 0
    game_over = False
    
    for _ in range(FRAMES):
        if game_over:
            frames.append({'snake': snake, 'food': food, 'score': score, 'game_over': True})
            continue
        
        if next_direction:
            opposite = {'up': 'down', 'down': 'up', 'left': 'right', 'right': 'left'}
            if opposite.get(next_direction) != direction:
                direction = next_direction
        
        head = snake[0]
        new_head = head.copy()
        if direction == 'right': new_head[0] += 1
        elif direction == 'left': new_head[0] -= 1
        elif direction == 'up': new_head[1] -= 1
        elif direction == 'down': new_head[1] += 1
        
        is_eating = (new_head[0] == food[0] and new_head[1] == food[1])
        new_snake = [new_head]
        end_index = len(snake) - (1 if is_eating else 0)
        for i in range(end_index):
            new_snake.append(snake[i])
        
        wall_collision = (new_head[0] < 0 or new_head[0] >= GRID_SIZE or 
                         new_head[1] < 0 or new_head[1] >= GRID_SIZE)
        head_str = f"{new_head[0]},{new_head[1]}"
        self_collision = False
        for i in range(1, len(new_snake)):
            if f"{new_snake[i][0]},{new_snake[i][1]}" == head_str:
                self_collision = True
                break
        
        if wall_collision or self_collision:
            game_over = True
            frames.append({'snake': new_snake, 'food': food, 'score': score, 'game_over': True})
            continue
        
        snake = new_snake
        if is_eating:
            score += 1
            snake_set = set(tuple(p) for p in snake)
            if len(snake_set) >= GRID_SIZE * GRID_SIZE:
                game_over = True
                frames.append({'snake': snake, 'food': food, 'score': score, 'game_over': True})
                continue
            new_food = None
            attempts = 0
            while attempts < 100:
                fx, fy = random.randint(0, GRID_SIZE-1), random.randint(0, GRID_SIZE-1)
                if (fx, fy) not in snake_set:
                    new_food = [fx, fy]
                    break
                attempts += 1
            if new_food:
                food = new_food
        
        frames.append({'snake': snake, 'food': food, 'score': score, 'game_over': False})
    
    return frames

def draw_frame(frame, frame_num):
    """绘制一帧"""
    img = Image.new('RGB', (CANVAS_SIZE, CANVAS_SIZE + 50), BG_COLOR)
    draw = ImageDraw.Draw(img)
    
    # 画网格
    for i in range(GRID_SIZE + 1):
        draw.line([(i*CELL_SIZE, 0), (i*CELL_SIZE, CANVAS_SIZE)], fill=GRID_COLOR, width=1)
        draw.line([(0, i*CELL_SIZE), (CANVAS_SIZE, i*CELL_SIZE)], fill=GRID_COLOR, width=1)
    
    # 画食物
    if not frame['game_over'] or frame_num == len(frames)-1:
        fx, fy = frame['food']
        cx, cy = fx*CELL_SIZE + CELL_SIZE//2, fy*CELL_SIZE + CELL_SIZE//2
        r = CELL_SIZE * 0.4
        draw.ellipse([cx-r, cy-r, cx+r, cy+r], fill=FOOD_COLOR)
        draw.ellipse([cx-r*0.5, cy-r*0.5, cx+r*0.3, cy+r*0.3], fill=(255, 138, 138))
    
    # 画蛇
    for i, (sx, sy) in enumerate(frame['snake']):
        x, y = sx*CELL_SIZE + 1, sy*CELL_SIZE + 1
        size = CELL_SIZE - 2
        if i == 0:
            color = SNAKE_HEAD
        else:
            ratio = i / len(frame['snake'])
            green = int(70 + 100 * (1 - ratio))
            color = (30, green, 70)
        draw.rounded_rectangle([x, y, x+size, y+size], radius=3, fill=color)
        
        # 蛇头眼睛
        if i == 0:
            # 简化版眼睛，根据方向调整
            eye_positions = {
                'right': [(x+8, y+3), (x+8, y+11)],
                'left': [(x+4, y+3), (x+4, y+11)],
                'up': [(x+3, y+5), (x+11, y+5)],
                'down': [(x+3, y+9), (x+11, y+9)]
            }
            eyes = eye_positions.get(frame.get('direction', 'right'), [(x+8, y+3), (x+8, y+11)])
            for ex, ey in eyes:
                draw.ellipse([ex-2, ey-2, ex+2, ey+2], fill=(240, 250, 244))
                draw.ellipse([ex-1, ey-1, ex+1, ey+1], fill=(10, 26, 26))
    
    # 画分数
    draw.text((10, CANVAS_SIZE + 12), f"🍎 分数: {frame['score']}", fill=(183, 228, 212), font=None)
    
    # 游戏结束
    if frame['game_over']:
        overlay = Image.new('RGBA', (CANVAS_SIZE, CANVAS_SIZE), (8, 18, 24, 190))
        img.paste(overlay, (0, 0), overlay)
        draw.text((CANVAS_SIZE//2-80, CANVAS_SIZE//2-10), "💀 游戏结束", fill=(242, 139, 130), font=None)
        draw.text((CANVAS_SIZE//2-60, CANVAS_SIZE//2+30), "刷新重看", fill=(189, 217, 208), font=None)
    
    return img

if __name__ == "__main__":
    print("🎮 生成贪吃蛇动画...")
    frames = generate_snake_frames()
    
    print(f"📊 总帧数: {len(frames)}")
    print(f"🏆 最终分数: {frames[-1]['score']}")
    print("🖼️  正在渲染 GIF...")
    
    # 生成所有帧
    images = []
    for i, frame in enumerate(frames):
        img = draw_frame(frame, i)
        images.append(img)
    
    # 保存为 GIF
    output_path = "snake.gif"
    if images:
        images[0].save(
            output_path,
            save_all=True,
            append_images=images[1:],
            duration=MOVE_INTERVAL,
            loop=0,
            optimize=True
        )
        print(f"✅ GIF 已生成: {output_path}")
